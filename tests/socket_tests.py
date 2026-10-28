#!/usr/bin/env python3
"""Exercise the real socket-mode daemon against local UDP/TCP upstreams; no public DNS."""
import concurrent.futures
import ipaddress
import json
import os
from pathlib import Path
import pwd
import secrets
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "admin"))
from net_accel_admin.config import unbound_configuration, DEFAULTS, DEFAULT_ROUTING


def query(name="cache.test", kind=1, transaction=1, edns=False):
    wire = struct.pack("!6H", transaction, 0x100, 1, 0, 0, int(edns))
    wire += b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\0"
    wire += struct.pack("!HH", kind, 1)
    if edns:
        wire += struct.pack("!BHHIH", 0, 41, 4096, 0, 0)
    return wire


class Upstream:
    def __init__(self, address=("127.0.0.1", 0), answer_ipv4="192.0.2.9"):
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(address)
        self.address = self.udp.getsockname()
        self.answer_ipv4 = answer_ipv4
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.bind(self.address)
        self.tcp.listen(16)
        self.count = {}
        self.stop = threading.Event()
        self.threads = [threading.Thread(target=self.serve_udp), threading.Thread(target=self.serve_tcp)]
        for thread in self.threads:
            thread.start()

    def answer(self, wire):
        cursor, labels = 12, []
        while wire[cursor]:
            length = wire[cursor]
            labels.append(wire[cursor+1:cursor+1+length].decode().lower())
            cursor += length + 1
        name = ".".join(labels)
        kind = struct.unpack_from("!H", wire, cursor+1)[0]
        end = cursor + 5
        self.count[name] = self.count.get(name, 0) + 1
        flags = 0x8183 if name.startswith("missing.") else 0x8180
        count = 0 if name.startswith(("missing.", "empty.")) else 1
        response = wire[:2] + struct.pack("!5H", flags, 1, count, 0, 0) + wire[12:end]
        if count:
            payload = ipaddress.IPv4Address(self.answer_ipv4).packed
            if kind == 28:
                payload = ipaddress.IPv6Address("2001:db8::9").packed
            elif kind == 65:
                payload = b"\0\1\0"
            elif kind == 16:
                payload = (b"\xfa" + b"x" * 250) * (6 if name.startswith("big.") else 1)
            response += struct.pack("!HHHIH", 0xc00c, kind, 1, 60, len(payload)) + payload
        return response

    def serve_udp(self):
        self.udp.settimeout(0.1)
        while not self.stop.is_set():
            try:
                wire, peer = self.udp.recvfrom(65535)
                self.udp.sendto(self.answer(wire), peer)
            except socket.timeout:
                pass

    def serve_tcp(self):
        self.tcp.settimeout(0.1)
        while not self.stop.is_set():
            try:
                client, _ = self.tcp.accept()
            except socket.timeout:
                continue
            with client:
                client.settimeout(2)
                while True:
                    try:
                        prefix = receive(client, 2, eof=True)
                        if not prefix:
                            break
                        response = self.answer(receive(client, struct.unpack("!H", prefix)[0]))
                        client.sendall(struct.pack("!H", len(response)) + response)
                    except OSError:
                        break

    def close(self):
        self.stop.set()
        for thread in self.threads:
            thread.join(3)
            assert not thread.is_alive()
        self.udp.close()
        self.tcp.close()


def receive(client, size, eof=False):
    data = b""
    while len(data) < size:
        part = client.recv(size - len(data))
        if not part:
            if eof and not data:
                return data
            raise OSError("short TCP frame")
        data += part
    return data


def exchange(port, wire, tcp=False):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as client:
        client.settimeout(3)
        client.connect(("127.0.0.1", port))
        if tcp:
            client.sendall(struct.pack("!H", len(wire)) + wire)
            result = receive(client, struct.unpack("!H", receive(client, 2))[0])
        else:
            client.send(wire)
            result = client.recv(65535)
        assert result[:2] == wire[:2] and result[2] & 0x80
        return result


def available_port(kind):
    with socket.socket(socket.AF_INET, kind) as client:
        client.bind(("127.0.0.1", 0))
        return client.getsockname()[1]


def main():
    binary = str(Path(sys.argv[1]).resolve())
    unbound = sys.argv[2] if len(sys.argv) > 2 and Path(sys.argv[2]).is_file() else None
    port, metrics = available_port(socket.SOCK_DGRAM), available_port(socket.SOCK_STREAM)
    cache = f"/net_accel_local_test_{os.getpid()}_{secrets.token_hex(6)}"
    upstream = Upstream()
    private = Upstream(answer_ipv4="100.64.0.9")
    deeper = Upstream(answer_ipv4="100.64.0.10")
    silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    silent.bind(("127.0.0.1", 0))
    zones = {"private.test": f"127.0.0.1:{private.address[1]}",
             "deep.private.test": f"127.0.0.1:{deeper.address[1]}",
             "offline.private.test": f"127.0.0.1:{silent.getsockname()[1]}"}
    zone_arguments = [part for name, target in zones.items() for part in ("--forward-zone", f"{name}={target}")]
    process = tcp_fallback = None
    try:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryFile(mode="w+") as log:
            notify_path = str(Path(directory) / "notify.sock")
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notify:
                notify.bind(notify_path)
                notify.settimeout(5)
                env = {**os.environ, "NOTIFY_SOCKET": notify_path}
                process = subprocess.Popen([binary, "--mode", "socket", "--bind", f"127.0.0.1:{port}",
                                            "--upstream", f"127.0.0.1:{upstream.address[1]}",
                                            "--cache-name", cache, "--metrics-port", str(metrics), *zone_arguments],
                                           env=env, stdout=log, stderr=log)
                assert b"READY=1" in notify.recv(1024), "supervisor did not report readiness"
            first = exchange(port, query())
            time.sleep(1.05)
            second = exchange(port, query("CACHE.test", transaction=9))
            assert second[12:len(query())] == query("CACHE.test")[12:]
            assert first[-4:] == second[-4:] == ipaddress.IPv4Address("192.0.2.9").packed
            assert struct.unpack_from("!I", second, len(query())+6)[0] < 60
            assert upstream.count["cache.test"] == 1
            for name, address in (("node.private.test", "100.64.0.9"), ("NODE.PRIVATE.TEST", "100.64.0.9"),
                                  ("node.deep.private.test", "100.64.0.10"), ("notprivate.test", "192.0.2.9")):
                assert exchange(port, query(name))[-4:] == ipaddress.IPv4Address(address).packed
            assert private.count["node.private.test"] == 1, "private replies must cache with their own upstream identity"
            assert exchange(port, query("missing.private.test"))[3] & 15 == 3
            assert exchange(port, query("node.offline.private.test"))[3] & 15 == 2
            assert "missing.private.test" not in upstream.count and "node.offline.private.test" not in upstream.count
            assert exchange(port, query(kind=28))[-16:] == ipaddress.IPv6Address("2001:db8::9").packed
            assert exchange(port, query(kind=65))[-3:] == b"\0\1\0"
            for _ in range(2):
                assert exchange(port, query("missing.test"))[3] & 15 == 3
                assert struct.unpack_from("!H", exchange(port, query("empty.test")), 6)[0] == 0
            assert upstream.count["missing.test"] == upstream.count["empty.test"] == 2
            big = query("big.test", kind=16, edns=True)
            assert exchange(port, big)[2] & 2, "oversized UDP answer must set TC"
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as bad:
                bad.sendto(b"invalid", ("127.0.0.1", port))
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(f"http://127.0.0.1:{metrics}/metrics", timeout=2) as response:
                text = response.read().decode()
                assert "net_accel_dns_hits_total" in text
            if unbound:
                config = {**DEFAULTS, "upstream": f"127.0.0.1:{upstream.address[1]}"}
                worker = "nobody" if os.geteuid() == 0 else pwd.getpwuid(os.getuid()).pw_name
                path = Path(directory) / "unbound.conf"
                text = unbound_configuration(config, worker, routing={**DEFAULT_ROUTING, "forward_zones": zones}).replace("127.0.0.1@53", f"127.0.0.1@{port}")
                # Unbound reserves .test locally; this fixture deliberately serves it upstream.
                text = text.replace("forward-zone:", '    local-zone: "test." transparent\nforward-zone:', 1)
                path.write_text(text)
                tcp_fallback = subprocess.Popen([unbound, "-d", "-c", str(path)], stdout=log, stderr=log)
                deadline = time.monotonic() + 5
                while True:
                    try:
                        full = exchange(port, big, tcp=True)
                        assert len(full) > 1232 and not full[2] & 2, (len(full), full[:12].hex())
                        private_full = exchange(port, query("big.private.test", kind=16, edns=True), tcp=True)
                        assert len(private_full) > 1232 and not private_full[2] & 2
                        assert "big.private.test" in private.count and "big.private.test" not in upstream.count
                        break
                    except OSError:
                        if tcp_fallback.poll() is not None:
                            log.seek(0)
                            raise RuntimeError("Unbound exited: " + log.read())
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.05)
            else:
                print("Unbound not installed: dedicated TCP fallback integration not run")
            started = time.perf_counter()
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(lambda i: exchange(port, query(transaction=i)), range(100)))
            print(json.dumps({"scenario": "localhost-warm-cache", "requests": 100,
                              "seconds": time.perf_counter() - started, "public_dns": False}))
            children = Path(f"/proc/{process.pid}/task/{process.pid}/children").read_text().split()
            assert len(children) == 1
            os.kill(int(children[0]), signal.SIGKILL)
            assert process.wait(timeout=5) == 128 + signal.SIGKILL
            log.seek(0)
            output = log.read()
            assert "Local DNS ready" in output and "load BPF" not in output, output
    finally:
        for child in (process, tcp_fallback):
            if child and child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
        upstream.close()
        private.close()
        deeper.close()
        silent.close()
        try:
            Path("/dev/shm", cache[1:]).unlink()
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    main()
