"""Local DNS service preparation and validated restarts. No control server."""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import pwd
import secrets
import socket
import struct
import subprocess
import tempfile
import time

from .config import (CACHE_NAME, DEFAULTS, DEFAULT_ROUTING, atomic_write, daemon_arguments,
                     read_json, unbound_configuration, validate, validate_routing, write_json)

UNITS = ("net-accel-dns.service", "net-accel-dns-tcp.service")


def dns_probe(tcp=False, address=("127.0.0.1", 53), timeout=2):
    transaction = secrets.randbelow(65536)
    query = struct.pack("!6H", transaction, 0x100, 1, 0, 0, 0) + b"\x07example\x03com\0\0\x01\0\x01"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as client:
        client.settimeout(timeout)
        deadline = time.monotonic() + timeout
        client.connect(address)
        if tcp:
            client.sendall(struct.pack("!H", len(query)) + query)

            def receive(size):
                data = b""
                while len(data) < size:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("TCP DNS probe deadline exceeded")
                    client.settimeout(remaining)
                    part = client.recv(size - len(data))
                    if not part:
                        raise OSError("incomplete TCP DNS response")
                    data += part
                return data

            response = receive(struct.unpack("!H", receive(2))[0])
        else:
            client.send(query)
            response = client.recv(65535)
        if len(response) < len(query) or response[:2] != query[:2]:
            raise OSError("invalid DNS probe response")
        flags, questions = struct.unpack_from("!HH", response, 2)
        # Readiness requires a complete standard response to our one question.
        # A truncated UDP reply only establishes that a TCP retry is needed.
        if not flags & 0x8000 or flags & (0x7800 | 0x0200 | 0x0040) or questions != 1:
            raise OSError("invalid DNS probe response")
        if response[3] & 15 not in (0, 3) or response[12:len(query)].lower() != query[12:]:
            raise OSError("DNS probe failed")


class Services:
    def __init__(self, daemon, systemctl="/usr/bin/systemctl", checkconf="/usr/sbin/unbound-checkconf"):
        self.daemon, self.systemctl, self.checkconf = daemon, systemctl, checkconf

    @staticmethod
    def run(args):
        result = subprocess.run(args, capture_output=True, text=True, timeout=20,
                                env={"PATH": "/usr/bin:/bin", "LANG": "C"})
        if result.returncode:
            raise RuntimeError((result.stderr or result.stdout or "service command failed")[-2000:].strip())
        return result.stdout

    def validate(self, config, unbound_path, routing=None):
        self.run([self.daemon, *daemon_arguments(config, routing=routing), "--check-config"])
        self.run([self.checkconf, str(unbound_path)])

    def stop(self):
        self.run([self.systemctl, "stop", *UNITS])

    def start(self):
        # A deliberate validated update gets a fresh start budget. Automatic crash
        # recovery still obeys systemd's limit, so an unattended crash loop stops.
        self.run([self.systemctl, "reset-failed", *UNITS])
        self.run([self.systemctl, "start", *UNITS])

    def healthy(self):
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            try:
                dns_probe()
                dns_probe(tcp=True)
                return
            except OSError:
                time.sleep(0.2)
        raise RuntimeError("UDP/TCP DNS readiness probes failed")

    def status(self):
        states = {}
        for unit in UNITS:
            result = subprocess.run([self.systemctl, "is-active", unit], capture_output=True, text=True, timeout=3)
            states[unit] = result.stdout.strip() or "unknown"
        return states

    def daily_status(self):
        result = subprocess.run([self.systemctl, "is-active", "net-accel-dns-daily.service"],
                                capture_output=True, text=True, timeout=3)
        return result.stdout.strip() or "unknown"

    def failure_reason(self, unit):
        if unit not in UNITS:
            raise ValueError("unsupported service")
        fallback = "DNS service is unavailable; check its service logs."
        try:
            journalctl = str(Path(self.systemctl).with_name("journalctl"))
            result = subprocess.run([journalctl, "--unit", unit, "--lines", "30", "--output=cat", "--no-pager"],
                                    capture_output=True, text=True, timeout=3)
        except (OSError, subprocess.SubprocessError):
            return fallback
        if result.returncode:
            return fallback
        for line in reversed(result.stdout.splitlines()):
            if line.startswith(("dns_daemon:", "dns_daemon worker:")):
                if "bind localhost UDP: Address already in use" in line:
                    return "UDP port 127.0.0.1:53 is already in use. Stop the manually started DNS daemon, then run sudo dnsctl restart."
                if "metrics bind/listen failed: Address already in use" in line:
                    return "Metrics port 127.0.0.1:19091 is already in use. Stop the conflicting process, then run sudo dnsctl restart."
                return line[:600]
        return fallback


class Controller:
    def __init__(self, state, runtime, services, routing=None):
        self.state, self.runtime = Path(state), Path(runtime)
        self.services = services
        self.routing = validate_routing(DEFAULT_ROUTING if routing is None else routing)

    @contextmanager
    def lock(self):
        with open(self.state / "control.lock", "a", encoding="utf-8") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            yield

    def config(self):
        return validate(read_json(self.state / "settings.json"))

    def prepare(self):
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.runtime.mkdir(mode=0o755, parents=True, exist_ok=True)
        with self.lock():
            if not (self.state / "settings.json").exists():
                write_json(self.state / "settings.json", DEFAULTS)
            journal = self.state / "transaction.json"
            if journal.exists():
                previous = validate(read_json(journal)["previous"])
                write_json(self.state / "settings.json", previous)
                self.record("recovered", "Interrupted update restored; services will start with previous settings")
                journal.unlink()
            atomic_write(self.runtime / "unbound.conf", unbound_configuration(self.config(), routing=self.routing), 0o644)

    def record(self, result, message):
        write_json(self.state / "last-result.json", {"result": result, "message": message, "time": int(time.time())})

    def invalidate_cache(self):
        path = Path("/dev/shm") / CACHE_NAME[1:]
        try:
            info = path.lstat()
        except FileNotFoundError:
            return
        import stat
        if not stat.S_ISREG(info.st_mode) or info.st_uid != pwd.getpwnam("net-accel-dns").pw_uid or info.st_mode & 0o077:
            raise RuntimeError("managed cache ownership or permissions are unexpected")
        path.unlink()

    def apply(self, candidate, expected, restart=False):
        with self.lock():
            previous = self.config()
            if type(expected) is not int or previous["revision"] != expected:
                raise ValueError("settings changed; refresh before applying")
            candidate = validate(candidate)
            candidate["revision"] = previous["revision"] + 1
            candidate = validate(candidate)
            fd, path = tempfile.mkstemp(dir=self.state, prefix="unbound-check-")
            os.close(fd)
            try:
                atomic_write(path, unbound_configuration(candidate, routing=self.routing))
                self.services.validate(candidate, path, self.routing)
            finally:
                os.unlink(path)
            write_json(self.state / "transaction.json", {"previous": previous})
            try:
                self.services.stop()
                if (candidate["upstream"], candidate["transport"]) != (previous["upstream"], previous["transport"]):
                    self.invalidate_cache()
                write_json(self.state / "settings.json", candidate)
                atomic_write(self.runtime / "unbound.conf", unbound_configuration(candidate, routing=self.routing), 0o644)
                self.services.start()
                self.services.healthy()
            except Exception as error:
                try:
                    self.services.stop()
                    self.invalidate_cache()
                    # Keep revisions increasing, including rollbacks, to reject stale clients.
                    previous["revision"] = candidate["revision"] + 1
                    write_json(self.state / "settings.json", previous)
                    atomic_write(self.runtime / "unbound.conf", unbound_configuration(previous, routing=self.routing), 0o644)
                    self.services.start()
                    self.services.healthy()
                except Exception as recovery:
                    self.record("failed", f"Update failed: {error}; recovery failed: {recovery}")
                    raise RuntimeError("Update and recovery failed; inspect service logs") from recovery
                (self.state / "transaction.json").unlink()
                self.record("rolled_back", f"Update rejected and previous settings restored: {error}")
                raise RuntimeError("Update failed; previous settings were restored") from error
            if not restart:
                write_json(self.state / "previous.json", previous)
            (self.state / "transaction.json").unlink()
            self.record("applied", "Services restarted and UDP/TCP DNS probes passed")
            return {"config": candidate, "last_result": read_json(self.state / "last-result.json")}
