#!/usr/bin/env python3
"""Concurrent warm-cache DNS RTT benchmark; run from a separate client."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import socket
import statistics
import struct
import time
from xdp_smoke import question

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("server", help="IPv4 address of the accelerator")
parser.add_argument("--label", required=True, help="Verified daemon mode and hardware/run identifier")
parser.add_argument("--port", type=int, default=53)
parser.add_argument("--count", type=int, default=10000)
parser.add_argument("--concurrency", type=int, default=1)
parser.add_argument("--timeout", type=float, default=1)
parser.add_argument("--name", default="a.test", help="Name with a positive cacheable answer")
args = parser.parse_args()
if not 1 <= args.count <= 1000000 or not 1 <= args.concurrency <= min(256, args.count):
    parser.error("count must be 1..1000000 and concurrency 1..min(256,count)")
if not 1 <= args.port <= 65535:
    parser.error("port must be 1..65535")
if not 0 < args.timeout <= 10:
    parser.error("timeout must be greater than zero and at most 10 seconds")
socket.inet_pton(socket.AF_INET, args.server)

def query(sock, transaction):
    request = question(args.name, 1, transaction)
    started = time.perf_counter_ns()
    sock.send(request)
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        sock.settimeout(max(0.001, deadline - time.monotonic()))
        response = sock.recv(65535)
        if len(response) < 12 or struct.unpack_from("!H", response)[0] != transaction:
            continue
        flags, qd, an = struct.unpack_from("!3H", response, 2)
        if flags & 0x8000 and not flags & 0x020F and qd == 1 and an and response[12:len(request)] == request[12:]:
            return (time.perf_counter_ns() - started) / 1000
        raise ValueError("expected a complete positive response")
    raise TimeoutError("no matching response")

def connect():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((args.server, args.port))
    sock.settimeout(args.timeout)
    return sock

with connect() as sock:
    query(sock, 0)  # Warm once. Failures abort the run.

def worker(index):
    latencies, errors = [], 0
    with connect() as sock:
        for attempt in range(index, args.count, args.concurrency):
            try:
                latencies.append(query(sock, (attempt + 1) % 65536))
            except (OSError, ValueError):
                errors += 1
    return latencies, errors

started = time.perf_counter()
with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
    results = list(pool.map(worker, range(args.concurrency)))
elapsed = time.perf_counter() - started
latencies = sorted(value for values, _ in results for value in values)
errors = sum(errors for _, errors in results)
def percentile(p):
    return latencies[min(len(latencies) - 1, int((len(latencies) - 1) * p))] if latencies else None
report = dict(label=args.label, server=args.server, name=args.name, attempted=args.count,
              concurrency=args.concurrency, completed=len(latencies), errors=errors,
              success_ratio=len(latencies) / args.count, seconds=elapsed, completed_qps=len(latencies) / elapsed,
              median_us=statistics.median(latencies) if latencies else None, p95_us=percentile(.95), p99_us=percentile(.99))
if args.concurrency == 1:
    report["sequential_qps"] = report["completed_qps"]
print(json.dumps(report, indent=2))
raise SystemExit(bool(errors))
