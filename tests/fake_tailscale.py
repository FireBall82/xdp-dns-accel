#!/usr/bin/env python3
"""Tailscale preference fixture, used only by the standalone deployment VM."""
import json
from pathlib import Path
import sys

path = Path('/var/lib/net-accel-dns/test-tailscale.json')
if not path.exists():
    path.write_text('true')
args = sys.argv[1:]
if args == ['debug', 'prefs']:
    print(json.dumps({'CorpDNS': json.loads(path.read_text())}))
elif args == ['status', '--json']:
    print(json.dumps({'CurrentTailnet': {'MagicDNSSuffix': 'tailtest.ts.net'},
                      'Self': {'DNSName': 'machine.tailtest.ts.net.'}}))
elif len(args) == 2 and args[0] == 'set' and args[1] in ('--accept-dns=true', '--accept-dns=false'):
    path.write_text(args[1].split('=')[1])
else:
    raise SystemExit('unexpected fixture command')
