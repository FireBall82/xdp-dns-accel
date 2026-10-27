#!/usr/bin/env python3
"""Sequential warm-cache DNS latency benchmark; run from a remote client."""
import argparse
import json
import socket
import statistics
import struct
import time
from xdp_smoke import question

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("server", help="IPv4 address of the accelerator")
parser.add_argument("--label", required=True, help="Verified daemon mode and hardware/run identifier")
parser.add_argument("--count", type=int, default=10000)
parser.add_argument("--name", default="a.test", help="Name with a positive cacheable answer")
args = parser.parse_args()
if args.count < 1:
    parser.error("count must be positive")
latencies = []
errors = 0
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.connect((args.server, 53))
    sock.settimeout(1)
    def query(transaction):
        request = question(args.name, 1, transaction)
        started = time.perf_counter_ns()
        sock.send(request)
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            response = sock.recv(65535)
            if len(response) < 12 or struct.unpack_from("!H", response)[0] != transaction:
                continue
            flags, qd, an = struct.unpack_from("!3H", response, 2)
            if flags & 0x8000 and not flags & 0x020F and qd == 1 and an and response[12:len(request)] == request[12:]:
                return (time.perf_counter_ns() - started) / 1000
            raise ValueError("expected a complete positive response")
        raise TimeoutError("no matching response")
    query(0)  # Warm the cache; failures abort the run.
    started = time.perf_counter()
    for index in range(args.count):
        try:
            latencies.append(query((index + 1) % 65536))
        except (OSError, ValueError):
            errors += 1
    elapsed = time.perf_counter() - started
latencies.sort()
def percentile(p):
    return latencies[min(len(latencies) - 1, int((len(latencies) - 1) * p))] if latencies else None
print(json.dumps(dict(label=args.label, server=args.server, name=args.name, attempted=args.count,
                      completed=len(latencies), errors=errors, seconds=elapsed,
                      sequential_qps=len(latencies) / elapsed, median_us=statistics.median(latencies) if latencies else None,
                      p95_us=percentile(.95), p99_us=percentile(.99)), indent=2))
raise SystemExit(bool(errors))
