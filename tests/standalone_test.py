#!/usr/bin/env python3
"""Standalone enable/disable/reboot acceptance without importing the NixOS module."""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

from deployment_test import run, wait_until
from net_accel_admin.config import DEFAULTS, write_json
from socket_tests import exchange, query


def lookup(name, address):
    actual = {item[4][0] for item in socket.getaddrinfo(name, 443, socket.AF_INET)}
    assert actual == {address}, (name, actual)


def main():
    assert os.geteuid() == 0 and os.environ.get('NET_ACCEL_ISOLATED_TEST') == '1'
    cli, phase = sys.argv[1:]
    state = Path('/var/lib/net-accel-dns')
    configuration = Path('/etc/nixos/configuration.nix')
    before = configuration.read_bytes()
    profile = Path('/run/NetworkManager/system-connections/daily-test.nmconnection')
    profile_before = profile.read_bytes()
    try:
        if phase == 'before':
            state.mkdir(mode=0o700, exist_ok=True)
            lookup('baseline.example.com', '198.51.100.1')
            write_json(state / 'settings.json', {**DEFAULTS, 'upstream': '127.0.0.1:15355'})
            rejected = subprocess.run([cli, 'enable'], capture_output=True, text=True, timeout=90)
            assert rejected.returncode != 0, 'Unreachable upstream should reject activation'
            assert not (state / 'daily-install.json').exists(), rejected.stderr
            assert not Path('/usr/local/lib/systemd/system-generators/net-accel-dns-daily').exists()
            assert run('systemctl', 'is-active', 'net-accel-dns') == 'active'
            lookup('rejected.example.com', '198.51.100.1')
            write_json(state / 'settings.json', {**DEFAULTS, 'upstream': '127.0.0.1:15353'})
            print(run(cli, 'enable'))
        assert run('systemctl', 'is-active', 'net-accel-dns-daily') == 'active'
        assert 'nameserver 127.0.0.1' in Path('/etc/resolv.conf').read_text()
        lookup(phase + '.example.com', '192.0.2.9')
        lookup(phase + '.tailtest.ts.net', '100.64.0.9')
        lookup('short' + phase, '100.64.0.9')
        assert len(exchange(53, query('big.tailtest.ts.net', kind=16), tcp=True)) > 1500
        time.sleep(0.2)
        counts = json.loads(Path('/var/lib/daily-fixture-counts.json').read_text())
        assert not any(name.endswith('ts.net') for name in counts['public']), counts
        assert not json.loads((state / 'test-tailscale.json').read_text())
        status = json.loads(run(cli, 'status', '--json'))
        assert status['daily_service'] == 'active' and status['metrics'] is not None
        unprivileged = json.loads(run('runuser', '-u', 'nobody', '--', cli, 'status', '--json'))
        assert unprivileged['daily_service'] == 'active' and unprivileged['metrics'] is not None
        if phase == 'before':
            print(run(cli, 'restart'))
            lookup('restarted.example.com', '192.0.2.9')
            # Killing a supervised process must restore original DNS while the
            # unit restarts; system lookups must still work through the baseline.
            supervisor = int(run('systemctl', 'show', '--property=MainPID', '--value', 'net-accel-dns-daily'))
            children = Path(f'/proc/{supervisor}/task/{supervisor}/children').read_text().split()
            assert len(children) == 2
            os.kill(int(children[0]), signal.SIGKILL)
            wait_until(lambda: not (state / 'daily-network.json').exists())
            lookup('during-recovery.example.com', '198.51.100.1')
            def recovered():
                pid = int(run('systemctl', 'show', '--property=MainPID', '--value', 'net-accel-dns-daily'))
                return pid > 0 and pid != supervisor and run('systemctl', 'is-active', 'net-accel-dns-daily') == 'active'
            wait_until(recovered, timeout=45)
            lookup('recovered.example.com', '192.0.2.9')
        print(run(cli, 'disable'))
        wait_until(lambda: lookup('disabled-' + phase + '.example.com', '198.51.100.1') is None)
        assert json.loads((state / 'test-tailscale.json').read_text())
        assert not Path('/run/NetworkManager/conf.d/90-net-accel-dns.conf').exists()
        assert not Path('/usr/local/lib/systemd/system-generators/net-accel-dns-daily').exists()
        assert run('systemctl', 'is-active', 'net-accel-dns') == 'active'
        assert run('systemctl', 'is-active', 'net-accel-dns-tcp') == 'active'
        assert configuration.read_bytes() == before
        assert profile.read_bytes() == profile_before
        if phase == 'before':
            print(run(cli, 'enable'))
        print('Standalone ' + phase + ': system/private DNS, rollback and unchanged NixOS configuration passed')
    except Exception:
        print(Path('/etc/resolv.conf').read_text(), flush=True)
        subprocess.run(['nmcli', 'connection', 'show', '--active'], check=False)
        subprocess.run(['nmcli', 'device', 'show'], check=False)
        subprocess.run(['journalctl', '--no-pager', '-n', '120', '-u', 'net-accel-dns-daily', '-u', 'NetworkManager'], check=False)
        raise


if __name__ == '__main__':
    main()
