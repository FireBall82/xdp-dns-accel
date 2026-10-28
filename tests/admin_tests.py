#!/usr/bin/env python3
"""Service configuration, private routing, and restart transactions."""
import copy
import json
import os
import struct
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "admin"))
from net_accel_admin.config import (DEFAULTS, DEFAULT_ROUTING, daemon_arguments, load_routing,
                                   unbound_configuration, validate, validate_routing, read_json, write_json)
from net_accel_admin.control import Controller, Services, dns_probe


class FakeServices:
    def __init__(self):
        self.failure = 0
        self.running = True

    def validate(self, config, path, routing=None):
        assert Path(path).read_text().startswith("server:")
        if config["workers"] == 63:
            raise RuntimeError("configuration rejected")

    def stop(self):
        self.running = False

    def start(self):
        self.running = True

    def healthy(self):
        if self.failure:
            self.failure -= 1
            raise RuntimeError("readiness failed")

    def status(self):
        return {"net-accel-dns.service": "active", "net-accel-dns-tcp.service": "active"}


class ProbeValidation(unittest.TestCase):
    def test_readiness_rejects_truncated_and_invalid_headers(self):
        question = b"\x07example\x03com\0\0\x01\0\x01"
        for flags, questions, valid in ((0x8180, 1, True), (0x8183, 1, True),
                                         (0x8380, 1, False), (0x8980, 1, False),
                                         (0x81c0, 1, False), (0x0180, 1, False),
                                         (0x8180, 0, False), (0x8180, 2, False)):
            with self.subTest(flags=hex(flags), questions=questions):
                response = struct.pack("!6H", 123, flags, questions, 0, 0, 0) + question
                with patch("net_accel_admin.control.secrets.randbelow", return_value=123), \
                     patch("net_accel_admin.control.socket.socket") as socket_factory:
                    socket_factory.return_value.__enter__.return_value.recv.return_value = response
                    if valid:
                        dns_probe()
                    else:
                        with self.assertRaises(OSError):
                            dns_probe()


class ServiceDiagnostics(unittest.TestCase):
    def test_reports_the_udp_port_conflict(self):
        services = Services("/daemon")
        logs = "dns_daemon: bind localhost UDP: Address already in use\nFailed to start DNS resolver.\n"
        with patch("net_accel_admin.control.subprocess.run", return_value=subprocess.CompletedProcess([], 0, logs)):
            reason = services.failure_reason("net-accel-dns.service")
        self.assertIn("127.0.0.1:53", reason)
        self.assertIn("manually started", reason)

    def test_uses_latest_worker_error_and_limits_output(self):
        services = Services("/daemon")
        logs = "dns_daemon: bind localhost UDP: Address already in use\ndns_daemon worker: cache ownership mismatch\n"
        with patch("net_accel_admin.control.subprocess.run", return_value=subprocess.CompletedProcess([], 0, logs)):
            self.assertEqual(services.failure_reason("net-accel-dns.service"), "dns_daemon worker: cache ownership mismatch")
        with patch("net_accel_admin.control.subprocess.run", side_effect=OSError("unavailable")):
            self.assertIn("service logs", services.failure_reason("net-accel-dns.service"))
        with self.assertRaises(ValueError):
            services.failure_reason("arbitrary.service")


class DeploymentRouting(unittest.TestCase):
    def test_routes_are_shared_by_udp_and_tcp(self):
        routing = {**DEFAULT_ROUTING, "system_dns": True, "search_domains": ["TAIL.TEST."],
                   "forward_zones": {"TAIL.TEST.": "100.100.100.100"}}
        normalized = validate_routing(routing)
        self.assertEqual(normalized["forward_zones"], {"tail.test": "100.100.100.100:53"})
        self.assertEqual(normalized["search_domains"], ["tail.test"])
        args = daemon_arguments(DEFAULTS, routing=routing)
        self.assertEqual(args[-2:], ["--forward-zone", "tail.test=100.100.100.100:53"])
        tcp = unbound_configuration(DEFAULTS, routing=routing)
        self.assertIn('local-zone: "tail.test." transparent', tcp)
        self.assertIn('name: "tail.test."', tcp)
        self.assertIn('forward-addr: 100.100.100.100@53', tcp)
        self.assertIn('forward-first: no', tcp)

    def test_rejects_routing_injection_duplicates_and_loops(self):
        for zones in ({".": "1.1.1.1"}, {"test\nserver:": "1.1.1.1"},
                      {"a..test": "1.1.1.1"}, {"test": "127.0.0.53"},
                      {"test": "127.0.0.1"}, {"test": "127.0.0.54:53"},
                      {"TEST": "1.1.1.1", "test.": "8.8.8.8"}):
            with self.subTest(zones=zones), self.assertRaises(ValueError):
                validate_routing({**DEFAULT_ROUTING, "forward_zones": zones})
        for address in ("127.0.0.53", "127.0.0.54:53"):
            with self.assertRaises(ValueError):
                validate({**DEFAULTS, "upstream": address})

    def test_no_routing_file_preserves_standalone_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(load_routing(Path(directory) / "missing"), DEFAULT_ROUTING)


class Transactions(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.services = FakeServices()
        self.controller = Controller(root / "state", root / "run", self.services)
        self.controller.prepare()
        self.controller.invalidate_cache = lambda: None

    def tearDown(self):
        self.temporary.cleanup()

    def test_validate_rejects_unknown_and_unsafe_values(self):
        for key, value in (("upstream", "127.0.0.1"), ("upstream", "0.0.0.0"),
                           ("upstream", "1.1.1.1:53;id"), ("upstream", "1.1.1.1:-1"),
                           ("workers", True), ("workers", 0), ("rate_limit", -1),
                           ("transport", "tls"), ("version", 2), ("bind", "0.0.0.0:53")):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                validate({**DEFAULTS, key: value})
        self.assertEqual(validate({**DEFAULTS, "upstream": "192.0.2.1"})["upstream"], "192.0.2.1:53")

    def test_apply_and_stale_revision(self):
        result = self.controller.apply({**DEFAULTS, "workers": 8}, 1)
        self.assertEqual(result["config"]["revision"], 2)
        self.assertEqual(self.controller.config()["workers"], 8)
        self.assertFalse((self.controller.state / "transaction.json").exists())
        with self.assertRaisesRegex(ValueError, "refresh"):
            self.controller.apply(self.controller.config(), 1, restart=True)

    def test_validation_failure_keeps_existing_configuration(self):
        with self.assertRaisesRegex(RuntimeError, "rejected"):
            self.controller.apply({**DEFAULTS, "workers": 63}, 1)
        self.assertEqual(self.controller.config(), DEFAULTS)
        self.assertTrue(self.services.running)

    def test_failed_activation_restores_previous_configuration(self):
        self.services.failure = 1
        with self.assertRaisesRegex(RuntimeError, "previous settings were restored"):
            self.controller.apply({**DEFAULTS, "workers": 9}, 1)
        self.assertEqual(self.controller.config()["workers"], 4)
        self.assertEqual(self.controller.config()["revision"], 3)
        self.assertEqual(read_json(self.controller.state / "last-result.json")["result"], "rolled_back")
        self.assertTrue(self.services.running)

    def test_failed_recovery_retains_journal(self):
        self.services.failure = 2
        with self.assertRaisesRegex(RuntimeError, "recovery failed"):
            self.controller.apply({**DEFAULTS, "workers": 9}, 1)
        self.assertTrue((self.controller.state / "transaction.json").exists())
        self.controller.prepare()
        self.assertEqual(self.controller.config()["workers"], 4)
        self.assertFalse((self.controller.state / "transaction.json").exists())

    def test_explicit_rollback(self):
        self.controller.apply({**DEFAULTS, "workers": 8}, 1)
        result = self.controller.apply(read_json(self.controller.state / "previous.json"), 2)
        self.assertEqual(result["config"]["workers"], 4)
        self.assertEqual(result["config"]["revision"], 3)

    def test_upstream_changes_preserve_private_routes(self):
        routing = {**DEFAULT_ROUTING, "forward_zones": {"private.test": "100.100.100.100"}}
        controller = Controller(self.controller.state, self.controller.runtime, self.services, routing)
        controller.invalidate_cache = lambda: None
        controller.apply({**DEFAULTS, "upstream": "8.8.8.8"}, 1)
        self.assertEqual(controller.routing["forward_zones"], {"private.test": "100.100.100.100:53"})
        self.assertIn("100.100.100.100@53", (controller.runtime / "unbound.conf").read_text())
        self.assertNotIn("forward_zones", controller.config())

    def test_concurrent_edits_are_serialized(self):
        outcomes = []

        def apply(workers):
            try:
                self.controller.apply({**DEFAULTS, "workers": workers}, 1)
                outcomes.append("ok")
            except ValueError:
                outcomes.append("stale")

        threads = [threading.Thread(target=apply, args=(workers,)) for workers in (7, 8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(3)
        self.assertCountEqual(outcomes, ["ok", "stale"])



if __name__ == "__main__":
    unittest.main()
