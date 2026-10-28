#!/usr/bin/env python3
"""Check reversible DNS ownership and generated standalone boot integration."""
import argparse
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'admin'))
from net_accel_admin import daily
from net_accel_admin.config import DEFAULT_ROUTING, write_json


class DailyServiceTests(unittest.TestCase):
    def test_generator_has_boot_dependency_and_no_main_config_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            template = root / 'unit'
            template.write_text('[Service]\nExecStart=/package/bin/dnsctl daily-run\n')
            output = root / 'early'
            daily.generate(output, template)
            self.assertEqual((output / daily.UNIT).read_text(), template.read_text())
            self.assertEqual((output / 'multi-user.target.wants' / daily.UNIT).resolve(), output / daily.UNIT)
            for unit in daily.LEGACY:
                self.assertEqual((output / unit).readlink(), Path('/dev/null'))

    def test_routes_and_searches_are_validated(self):
        routes = daily.routing_for(DEFAULT_ROUTING, ['TAIL.TEST.'], True)
        self.assertEqual(len(routes['forward_zones']), 66)
        self.assertEqual(routes['search_domains'], ['tail.test'])
        self.assertIn('64.100.in-addr.arpa', routes['forward_zones'])
        self.assertIn('127.100.in-addr.arpa', routes['forward_zones'])
        self.assertIn('servers=127.0.0.1', daily.nm_configuration(routes['search_domains']))
        with self.assertRaises(ValueError):
            daily.nm_configuration(['test\n[main]'])

    def test_restore_is_idempotent_and_preserves_previous_tailscale_preference(self):
        for preference in (True, False, None):
            with self.subTest(preference=preference), tempfile.TemporaryDirectory() as directory:
                state = Path(directory)
                snippet = state / 'runtime.conf'
                text = daily.nm_configuration(['tail.test'])
                snippet.write_text(text)
                write_json(state / 'daily-network.json', {'nm_configuration': text, 'tailscale_accept_dns': preference})
                args = argparse.Namespace(nmcli='/nmcli', tailscale='/tailscale')
                with patch.object(daily, 'STATE', state), patch.object(daily, 'NM_CONFIG', snippet), patch.object(daily, 'run') as run:
                    daily.restore(args)
                    daily.restore(args)
                self.assertFalse(snippet.exists())
                self.assertFalse((state / 'daily-network.json').exists())
                self.assertEqual(run.call_count, 1 if preference is None else 2)
                if preference is not None:
                    self.assertEqual(run.call_args.args[0][-1], '--accept-dns=' + str(preference).lower())

    def test_restore_rejects_external_changes_and_keeps_recovery_record(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            snippet = state / 'runtime.conf'
            snippet.write_text('changed outside this tool')
            backup = state / 'daily-network.json'
            write_json(backup, {'nm_configuration': 'original', 'tailscale_accept_dns': True})
            with patch.object(daily, 'STATE', state), patch.object(daily, 'NM_CONFIG', snippet), patch.object(daily, 'run') as run:
                with self.assertRaisesRegex(RuntimeError, 'externally'):
                    daily.restore(argparse.Namespace(nmcli='/nmcli', tailscale='/tailscale'))
            run.assert_not_called()
            self.assertTrue(backup.exists())
            self.assertEqual(snippet.read_text(), 'changed outside this tool')

    def test_tailscale_schema_is_checked_before_changing_anything(self):
        args = argparse.Namespace(systemctl='/systemctl', tailscale='/tailscale')
        with patch.object(daily, 'active', return_value=True), patch.object(daily, 'run', return_value='{}'):
            with self.assertRaisesRegex(ValueError, 'preference'):
                daily.tailscale_state(args)
        outputs = [json.dumps({'CorpDNS': True}), json.dumps({'CurrentTailnet': {'MagicDNSSuffix': 'TAIL.TEST.'}})]
        with patch.object(daily, 'active', return_value=True), patch.object(daily, 'run', side_effect=outputs):
            self.assertEqual(daily.tailscale_state(args), (True, ['tail.test']))


if __name__ == '__main__':
    unittest.main()
