#!/usr/bin/env python3
"""Exercise the terminal CLI with a real localhost metrics endpoint and PTY."""
import http.server
import json
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch

ADMIN = Path(__file__).resolve().parents[1] / 'admin'
sys.path.insert(0, str(ADMIN))
from net_accel_admin.monitor import measurements, parse_metrics

TEXT = '''net_accel_dns_received_total 10
net_accel_dns_hits_total 8
net_accel_dns_failures_total 0
net_accel_dns_job_queue_depth 1
net_accel_dns_reply_queue_depth 0
net_accel_dns_processing_seconds_sum 0.02
net_accel_dns_processing_seconds_count 10
'''


class CliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(TEXT.encode())
            def log_message(self, *args):
                pass
        cls.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def command(self, action, *args):
        return [sys.executable, '-m', 'net_accel_admin', '--systemctl', '/nonexistent/systemctl',
                action, '--metrics-port', str(self.server.server_port), *args]

    def environment(self):
        return {**os.environ, 'PYTHONPATH': str(ADMIN), 'HTTP_PROXY': 'http://127.0.0.1:1'}

    def run_cli(self, action, *args):
        return subprocess.run(self.command(action, *args), env=self.environment(),
                              capture_output=True, text=True, timeout=5)

    def test_status_and_finite_watch_without_login(self):
        result = self.run_cli('status')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('80.00%', result.stdout)
        self.assertIn('2.00 ms', result.stdout)
        self.assertNotIn('\033', result.stdout)
        result = self.run_cli('watch', '--json', '--samples', '2', '--interval', '0.2')
        self.assertEqual(result.returncode, 0, result.stderr)
        frames = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(len(frames), 2)
        self.assertIsNone(frames[0]['measurements']['queries_per_second'])
        self.assertEqual(frames[1]['measurements']['queries_per_second'], 0)

    def test_rate_and_worker_restart(self):
        previous = {'metrics': parse_metrics(TEXT), 'monotonic': 1}
        current = {'metrics': {**previous['metrics'], 'received_total': 20}, 'monotonic': 3}
        self.assertEqual(measurements(current, previous)['queries_per_second'], 5)
        current['metrics']['received_total'] = 0
        self.assertIsNone(measurements(current, previous)['queries_per_second'])
        self.assertIsNone(measurements(current)['cache_hit_percent'])
        with self.assertRaises(ValueError):
            parse_metrics(TEXT.replace('0.02', '1e999'))
        with self.assertRaises(ValueError):
            parse_metrics('not DNS metrics')

    def test_unavailable_and_removed_commands(self):
        with patch('net_accel_admin.monitor.urllib.request.OpenerDirector.open', side_effect=OSError('offline')):
            from net_accel_admin.monitor import snapshot
            from net_accel_admin.control import Services
            self.assertIn('offline', snapshot(Services('/unused', '/nonexistent/systemctl'))['error'])
        for args in (['watch', '--interval', 'nan'], ['watch', '--samples', '0'], ['web'], ['access-code', 'reset']):
            result = subprocess.run([sys.executable, '-m', 'net_accel_admin', *args], env=self.environment(),
                                    capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)

    def test_interrupt_restores_terminal(self):
        master, slave = pty.openpty()
        process = subprocess.Popen(self.command('watch', '--interval', '0.2'), env=self.environment(), stdout=slave, stderr=slave)
        os.close(slave)
        output = b''
        try:
            deadline = time.monotonic() + 5
            while b'Ctrl+C to exit' not in output and time.monotonic() < deadline:
                if select.select([master], [], [], 0.1)[0]:
                    output += os.read(master, 65536)
            self.assertIn(b'Ctrl+C to exit', output)
            process.send_signal(signal.SIGINT)
            self.assertEqual(process.wait(timeout=3), 0)
            while select.select([master], [], [], 0.1)[0]:
                try:
                    part = os.read(master, 65536)
                except OSError:
                    break
                if not part:
                    break
                output += part
            self.assertIn(b'\033[?25h\033[?1049l', output)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            os.close(master)


if __name__ == '__main__':
    unittest.main()
