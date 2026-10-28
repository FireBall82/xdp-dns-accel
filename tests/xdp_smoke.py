#!/usr/bin/env python3
"""Privileged, isolated veth/namespace smoke test. No external DNS is contacted."""
import ipaddress
import array
import fcntl
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import json
import threading
import urllib.request


def disable_tx_checksum(interface):
    """Equivalent to ethtool -K INTERFACE tx off, without an ethtool dependency."""
    encoded = interface.encode("ascii")
    if not encoded or len(encoded) > 15 or b"\0" in encoded:
        raise ValueError("invalid interface name")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
        def ethtool_value(command):
            value = array.array("I", [command, 0])
            request = struct.pack("16sP", encoded, value.buffer_info()[0]).ljust(40, b"\0")
            fcntl.ioctl(control.fileno(), 0x8946, request)  # SIOCETHTOOL
            return value[1]
        ethtool_value(0x17)  # ETHTOOL_STXCSUM: complete checksums in the sender.
        if ethtool_value(0x16):  # ETHTOOL_GTXCSUM: verify the setting took effect.
            raise RuntimeError("TX checksum offload is still enabled")
    print(f"Disabled TX checksum offload on {interface}", flush=True)


def question(name, qtype, transaction):
    encoded = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\0"
    return struct.pack("!6H", transaction, 0x100, 1, 0, 0, 0) + encoded + struct.pack("!HH", qtype, 1)


def mock_upstream():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("127.0.0.1", 15353))
        print("ready", flush=True)
        while True:
            wire, peer = server.recvfrom(65535)
            offset, labels = 12, []
            while wire[offset]:
                length = wire[offset]
                labels.append(wire[offset + 1:offset + 1 + length].decode("ascii").lower())
                offset += length + 1
            end = offset + 5
            name = ".".join(labels)
            qtype = struct.unpack_from("!H", wire, offset + 1)[0]
            rcode, answers, payload = 0, 1, b""
            if name == "missing.test":
                rcode, answers = 3, 0
            elif name == "empty.test":
                answers = 0
            elif qtype == 28:
                payload = ipaddress.IPv6Address("2001:db8::7").packed
            elif qtype == 16:
                payload = b"\4test"
            else:
                payload = ipaddress.IPv4Address("203.0.113.7").packed
            reply = struct.pack("!6H", struct.unpack_from("!H", wire)[0], 0x8180 | rcode, 1, answers, 0, 0) + wire[12:end]
            if answers:
                ttl = 0 if name == "zero.test" else 60
                reply += struct.pack("!HHHIH", 0xC00C, qtype, 1, ttl, len(payload)) + payload
            server.sendto(reply, peer)


def client():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.3)
        def resolve(name, qtype):
            transaction = secrets.randbelow(65536)
            request = question(name, qtype, transaction)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                sock.sendto(request, ("192.0.2.1", 53))
                try:
                    reply, peer = sock.recvfrom(65535)
                except (TimeoutError, OSError):
                    continue
                if peer != ("192.0.2.1", 53) or len(reply) < 12 or struct.unpack_from("!H", reply)[0] != transaction:
                    continue
                assert reply[12:len(request)] == request[12:], "question changed"
                return reply
            raise RuntimeError(f"no XDP response for {name} type {qtype}")
        first = resolve("a.test", 1)
        second = resolve("A.test", 1)
        assert first[-4:] == second[-4:] == ipaddress.IPv4Address("203.0.113.7").packed
        assert resolve("aaaa.test", 28)[-16:] == ipaddress.IPv6Address("2001:db8::7").packed
        assert resolve("txt.test", 16)[-5:] == b"\4test"
        missing = resolve("missing.test", 1)
        assert struct.unpack_from("!H", missing, 2)[0] & 15 == 3
        assert struct.unpack_from("!H", missing, 6)[0] == 0
        empty = resolve("empty.test", 1)
        assert struct.unpack_from("!H", empty, 6)[0] == 0
        zero = resolve("zero.test", 1)
        assert struct.unpack_from("!I", zero, len(question("zero.test", 1, 0)) + 6)[0] == 0
    print("XDP A/AAAA/TXT, cache, NXDOMAIN, NODATA and zero-TTL packets passed")


def security_client():
    # These source addresses exist only inside the temporary client namespace.
    def burst(source):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((source, 0))
            sock.settimeout(0.3)
            for transaction in (41000, 41001):
                sock.sendto(question("a.test", 1, transaction), ("192.0.2.1", 53))
            received = []
            try:
                while True:
                    wire, _ = sock.recvfrom(65535)
                    received.append(struct.unpack_from("!H", wire)[0])
            except TimeoutError:
                pass
            assert received == [41000], (source, received)
    burst("192.0.2.4")  # Per-client budget.
    burst("192.0.2.5")  # Per-network budget.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("192.0.2.2", 0))
        sock.settimeout(0.3)
        sock.sendto(question("a.test", 1, 42000), ("192.0.2.9", 53))
        try:
            wire, _ = sock.recvfrom(65535)
            raise AssertionError(f"wrong destination was accelerated: {wire!r}")
        except (TimeoutError, ConnectionRefusedError):
            pass
    def flood():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("192.0.2.3", 0))
            for transaction in range(2000):
                sock.sendto(question("a.test", 1, transaction), ("192.0.2.1", 53))
    attacker = threading.Thread(target=flood)
    attacker.start()
    latencies = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("192.0.2.2", 0))
        sock.settimeout(1)
        for transaction in range(100):
            started = time.perf_counter_ns()
            sock.sendto(question("a.test", 1, transaction), ("192.0.2.1", 53))
            wire, peer = sock.recvfrom(65535)
            assert peer == ("192.0.2.1", 53) and struct.unpack_from("!H", wire)[0] == transaction
            assert wire[-4:] == ipaddress.IPv4Address("203.0.113.7").packed
            latencies.append((time.perf_counter_ns() - started) / 1000)
    attacker.join()
    latencies.sort()
    print("Security load: " + json.dumps(dict(legitimate_attempted=100, legitimate_completed=len(latencies),
          unauthorized_sent=2000, median_us=latencies[49], p95_us=latencies[94], p99_us=latencies[98])), flush=True)


def check_security_metrics():
    deadline = time.monotonic() + 4
    expected = ["xdp_unauthorized_total", "destination_passed_total", "client_limited_total", "network_limited_total"]
    while time.monotonic() < deadline:
        with urllib.request.urlopen("http://127.0.0.1:19090/metrics", timeout=1) as response:
            body = response.read().decode()
        if all(re.search(r"net_accel_dns_" + name + r" [1-9][0-9]*\n", body) for name in expected):
            print(body, end="", flush=True)
            return
        time.sleep(0.05)
    raise AssertionError("security enforcement counters did not increase: " + body)


def smoke(daemon, xdp_mode="generic"):
    if os.geteuid() != 0:
        raise SystemExit("Run this smoke test with sudo; it creates only temporary namespaces and a veth pair.")
    daemon = str(Path(daemon).resolve(strict=True))
    script = str(Path(__file__).resolve())
    token = secrets.token_hex(4)
    server_ns, client_ns = f"dns-server-{token}", f"dns-client-{token}"
    server_if, client_if = f"ds{token}", f"dc{token}"
    cache = f"/net_accel_dns_smoke_{token}"
    upstream = process = None
    created_namespaces = []
    veth_created = False
    def run(*args, **kwargs):
        return subprocess.run(args, check=True, timeout=15, **kwargs)
    try:
        run("ip", "netns", "add", server_ns)
        created_namespaces.append(server_ns)
        run("ip", "netns", "add", client_ns)
        created_namespaces.append(client_ns)
        run("ip", "link", "add", server_if, "type", "veth", "peer", "name", client_if)
        veth_created = True
        run("ip", "link", "set", server_if, "netns", server_ns)
        run("ip", "link", "set", client_if, "netns", client_ns)
        for namespace, interface, address in [(server_ns, server_if, "192.0.2.1/24"), (client_ns, client_if, "192.0.2.2/24")]:
            run("ip", "-n", namespace, "link", "set", "lo", "up")
            run("ip", "-n", namespace, "address", "add", address, "dev", interface)
            run("ip", "-n", namespace, "link", "set", interface, "up")
            run("ip", "netns", "exec", namespace, sys.executable, script, "--disable-tx-checksum", interface)
        for address in ("192.0.2.3/24", "192.0.2.4/24", "192.0.2.5/24"):
            run("ip", "-n", client_ns, "address", "add", address, "dev", client_if)
        run("ip", "-n", server_ns, "address", "add", "192.0.2.9/24", "dev", server_if)
        with tempfile.TemporaryFile(mode="w+") as log:
            def read_log():
                return os.pread(log.fileno(), 1024 * 1024, 0).decode()
            def wait_worker(previous=0):
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    output = read_log()
                    pids = re.findall(r"Worker PID=([0-9]+) uid=([0-9]+)", output)
                    if len(pids) > previous and output.count("DNS accelerator ready:") == len(pids):
                        pid, uid = map(int, pids[-1])
                        assert uid != 0, "DNS worker retained root"
                        status = Path(f"/proc/{pid}/status").read_text()
                        for capability in ("CapInh", "CapPrm", "CapEff", "CapAmb"):
                            assert re.search(capability + r":\s+0+\n", status), status
                        assert re.search(r"NoNewPrivs:\s+1\n", status), status
                        return pid
                    if process.poll() is not None:
                        break
                    time.sleep(0.02)
                raise RuntimeError("worker did not start: " + read_log())
            command = ["ip", "netns", "exec", server_ns, daemon, server_if,
                       "--upstream", "127.0.0.1:15353", "--cache-name", cache,
                       "--xdp-mode", xdp_mode, "--xsk-mode", "copy", "--listen-address", "192.0.2.1",
                       "--allow-client", "192.0.2.2", "--allow-client", "192.0.2.4", "--allow-client", "192.0.2.5",
                       "--rate-limit", "10000", "--client-rate-limit", "1", "--network-rate-limit", "192.0.2.0/24:100",
                       "--network-rate-limit", "192.0.2.5/32:1", "--reserve-client", "192.0.2.2:1000", "--metrics-port", "19090"]
            upstream = subprocess.Popen(["ip", "netns", "exec", server_ns, sys.executable, script, "--mock"], stdout=log, stderr=log)
            deadline = time.monotonic() + 3
            while True:
                if "ready" in read_log():
                    break
                if upstream.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("mock DNS server did not start")
                time.sleep(0.02)
            process = subprocess.Popen(command, stdout=log, stderr=log)
            try:
                wait_worker()
                run("ip", "netns", "exec", client_ns, sys.executable, script, "--client")
                run("ip", "netns", "exec", client_ns, sys.executable, script, "--security-client")
                run("ip", "netns", "exec", server_ns, sys.executable, script, "--check-metrics")
                process.send_signal(signal.SIGTERM)
                process.wait(timeout=5)
                assert process.returncode == 0, "daemon failed during shutdown"
                output = read_log()
                print(output, end="")
                assert re.search(r"hits=[1-9][0-9]*", output), "no cache hit observed"
                assert f"XDP={xdp_mode} AF_XDP=copy" in output, "mode not verified"
                # The selected hook must have been removed on graceful shutdown.
                link = subprocess.check_output(["ip", "-n", server_ns, "-details", "link", "show", "dev", server_if], text=True)
                assert "prog/xdp" not in link, "XDP program left attached"
                # Abrupt worker death must also trigger supervisor cleanup.
                process = subprocess.Popen(command, stdout=log, stderr=log)
                worker = wait_worker(previous=1)
                os.kill(worker, signal.SIGKILL)
                process.wait(timeout=5)
                assert process.returncode == 128 + signal.SIGKILL, process.returncode
                link = subprocess.check_output(["ip", "-n", server_ns, "-details", "link", "show", "dev", server_if], text=True)
                assert "prog/xdp" not in link, "worker crash left XDP attached"
            except Exception:
                print(read_log(), file=sys.stderr)
                raise
    finally:
        for child in (process, upstream):
            if child and child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
        for namespace in created_namespaces:
            subprocess.run(["ip", "netns", "delete", namespace], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Handle setup failures before the veth ends have moved into namespaces.
        if veth_created:
            for interface in (server_if, client_if):
                subprocess.run(["ip", "link", "delete", interface], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        Path("/dev/shm" + cache).unlink(missing_ok=True)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--disable-tx-checksum":
        disable_tx_checksum(sys.argv[2])
    elif len(sys.argv) == 2 and sys.argv[1] == "--mock":
        mock_upstream()
    elif len(sys.argv) == 2 and sys.argv[1] == "--security-client":
        security_client()
    elif len(sys.argv) == 2 and sys.argv[1] == "--check-metrics":
        check_security_metrics()
    elif len(sys.argv) == 2 and sys.argv[1] == "--client":
        client()
    elif len(sys.argv) in (2, 3) and (len(sys.argv) == 2 or sys.argv[2] in ("generic", "native")):
        smoke(sys.argv[1], sys.argv[2] if len(sys.argv) == 3 else "generic")
    else:
        raise SystemExit("Usage: sudo python3 tests/xdp_smoke.py /path/to/dns_daemon [generic|native]\n"
                         "       sudo python3 tests/xdp_smoke.py --disable-tx-checksum INTERFACE")
