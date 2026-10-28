#!/usr/bin/env python3
"""Installed DNS services and terminal CLI acceptance in a disposable systemd VM."""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'admin'))
from socket_tests import Upstream
from net_accel_admin.cli import ensure_accounts
from net_accel_admin.config import DEFAULTS, write_json
from net_accel_admin.control import dns_probe


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def wait_until(check, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if check():
                return
        except (OSError, subprocess.CalledProcessError):
            pass
        time.sleep(0.2)
    raise AssertionError('service acceptance check timed out')


def main():
    if os.geteuid() != 0 or os.environ.get('NET_ACCEL_ISOLATED_TEST') != '1':
        raise SystemExit('Requires root in a disposable VM')
    cli = sys.argv[1]
    upstream = Upstream()
    units = ['net-accel-dns', 'net-accel-dns-tcp', 'net-accel-dns-prepare']
    try:
        run('systemctl', 'stop', *units)
        ensure_accounts()
        state = Path('/var/lib/net-accel-dns')
        state.mkdir(mode=0o700, exist_ok=True)
        write_json(state / 'settings.json', {**DEFAULTS, 'upstream': f'127.0.0.1:{upstream.address[1]}'})
        run('systemctl', 'start', *units)
        dns_probe()
        dns_probe(tcp=True)
        status = json.loads(run(cli, 'status', '--json'))
        assert status['metrics']['received_total'] >= 1
        assert all(value == 'active' for value in status['services'].values())
        # Monitoring really works for an unprivileged account, without a code.
        status = json.loads(run('runuser', '-u', 'nobody', '--', cli, 'status', '--json'))
        assert status['metrics'] is not None
        assert 'UDP example.com' in run(cli, 'check')
        frames = run(cli, 'watch', '--json', '--samples', '2', '--interval', '0.2').splitlines()
        assert len(frames) == 2 and json.loads(frames[1])['measurements']['queries_per_second'] is not None
        supervisor = int(run('systemctl', 'show', '--property=MainPID', '--value', 'net-accel-dns'))
        children = Path(f'/proc/{supervisor}/task/{supervisor}/children').read_text().split()
        assert len(children) == 1
        os.kill(int(children[0]), signal.SIGKILL)
        def restarted():
            pid = int(run('systemctl', 'show', '--property=MainPID', '--value', 'net-accel-dns'))
            return pid > 0 and pid != supervisor and run('systemctl', 'is-active', 'net-accel-dns') == 'active'
        wait_until(restarted)
        dns_probe()
        with socket.socket() as client:
            assert client.connect_ex(('127.0.0.1', 9080)) != 0, 'a removed web server is listening'
        print('Installed UDP/TCP DNS, unprivileged CLI, live monitoring and crash recovery passed')
    except Exception:
        subprocess.run(['journalctl', '--no-pager', '-n', '80', '-u', 'net-accel-dns', '-u', 'net-accel-dns-tcp'], check=False)
        raise
    finally:
        subprocess.run(['systemctl', 'stop', *units], check=False)
        upstream.close()


if __name__ == '__main__':
    main()
