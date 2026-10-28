#!/usr/bin/env python3
"""Offline DNS servers for the standalone service VM."""
import time
from pathlib import Path
from socket_tests import Upstream
from net_accel_admin.config import write_json

public = Upstream(('127.0.0.1', 15353))
private = Upstream(('100.100.100.100', 53), '100.64.0.9')
original = Upstream(('127.0.0.2', 53), '198.51.100.1')
while True:
    write_json(Path('/var/lib/daily-fixture-counts.json'),
               {'public': public.count.copy(), 'private': private.count.copy(), 'original': original.count.copy()})
    time.sleep(0.1)
