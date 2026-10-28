"""Exercise concurrent measurement and error accounting with local mock DNS."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys

for invalid_replies in (False, True):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("127.0.0.1", 0))
        server.settimeout(3)
        port = server.getsockname()[1]
        def respond():
            for index in range(33):
                wire, peer = server.recvfrom(65535)
                # The warmup succeeds; the second run rejects all measured responses.
                flags = 0x8182 if invalid_replies and index else 0x8180
                reply = struct.pack("!6H", struct.unpack_from("!H", wire)[0], flags, 1, 1, 0, 0)
                reply += wire[12:] + struct.pack("!HHHIH4s", 0xc00c, 1, 1, 60, 4, b"\xc0\x00\x02\x01")
                server.sendto(reply, peer)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(respond)
            result = subprocess.run([sys.executable, str(Path(__file__).with_name("benchmark.py")),
                                     "127.0.0.1", "--port", str(port), "--label", "local-test",
                                     "--count", "32", "--concurrency", "4"], capture_output=True, text=True, timeout=5)
            future.result()
        assert result.returncode == int(invalid_replies), result.stderr
        data = json.loads(result.stdout)
        assert data["attempted"] == 32 and data["concurrency"] == 4
        assert data["completed"] == (0 if invalid_replies else 32)
        assert data["errors"] == (32 if invalid_replies else 0)
        assert data["success_ratio"] == (0 if invalid_replies else 1)
        if not invalid_replies:
            assert data["completed_qps"] > 0 and data["p99_us"] >= data["median_us"] > 0
