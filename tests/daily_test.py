#!/usr/bin/env python3
"""Daily DNS acceptance in a disposable NixOS VM, using ordinary libc lookups."""
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess

from deployment_test import run, wait_until
from socket_tests import Upstream, query
from net_accel_admin.config import DEFAULTS, write_json


def lookup(name, expected):
    addresses = {item[4][0] for item in socket.getaddrinfo(name, 443, socket.AF_INET)}
    assert addresses == {expected}, (name, addresses)


def main():
    if os.geteuid() != 0 or os.environ.get("NET_ACCEL_ISOLATED_TEST") != "1":
        raise SystemExit("Requires root in a disposable VM")
    public = Upstream(("127.0.0.1", 15353))
    private = Upstream(("127.0.0.1", 15354), "100.64.0.9")
    units = ["net-accel-dns", "net-accel-dns-tcp", "net-accel-dns-prepare"]
    try:
        run("systemctl", "stop", *units)
        write_json(Path("/var/lib/net-accel-dns/settings.json"),
                   {**DEFAULTS, "upstream": "127.0.0.1:15353"})
        run("systemctl", "start", *units)
        run("systemctl", "restart", "systemd-resolved")
        assert "ordering cycle" not in run("journalctl", "-b", "--no-pager"), "boot dependency cycle"
        assert "nameserver 127.0.0.53" in Path("/etc/resolv.conf").read_text()
        assert "127.0.0.1" in run("resolvectl", "dns")
        lookup("daily.public.test", "192.0.2.9")
        lookup("host.private.test", "100.64.0.9")
        lookup("shortname", "100.64.0.9")
        assert private.count.get("shortname.private.test", 0) > 0
        assert not any(name.endswith("private.test") for name in public.count), public.count
        before = public.count["daily.public.test"]
        lookup("daily.public.test", "192.0.2.9")
        assert public.count["daily.public.test"] == before, "daemon cache was bypassed"
        wire = query("big.private.test", 16)
        with socket.create_connection(("127.0.0.1", 53), timeout=3) as client:
            client.sendall(struct.pack("!H", len(wire)) + wire)
            length = struct.unpack("!H", client.recv(2))[0]
            payload = b""
            while len(payload) < length:
                chunk = client.recv(length - len(payload))
                assert chunk
                payload += chunk
            assert length > 1500 and payload[3] & 15 == 0
        assert "big.private.test" not in public.count
        supervisor = int(run("systemctl", "show", "--property=MainPID", "--value", "net-accel-dns"))
        children = Path(f"/proc/{supervisor}/task/{supervisor}/children").read_text().split()
        assert len(children) == 1
        os.kill(int(children[0]), signal.SIGKILL)
        def restarted():
            pid = int(run("systemctl", "show", "--property=MainPID", "--value", "net-accel-dns"))
            return pid > 0 and pid != supervisor and run("systemctl", "is-active", "net-accel-dns") == "active"
        wait_until(restarted)
        lookup("recovered.public.test", "192.0.2.9")
        lookup("recovered.private.test", "100.64.0.9")
        print("Ordinary system DNS, private/search names, cache, TCP and crash recovery passed")
    except Exception:
        subprocess.run(["journalctl", "--no-pager", "-n", "100", "-u", "systemd-resolved",
                        "-u", "net-accel-dns", "-u", "net-accel-dns-tcp"], check=False)
        raise
    finally:
        public.close()
        private.close()


if __name__ == "__main__":
    main()
