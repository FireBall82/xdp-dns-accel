"""Read-only terminal monitoring of the localhost DNS worker; no login or settings UI."""
import json
import math
import re
import subprocess
import sys
import time
import urllib.request

MAX_METRICS = 131072


def parse_metrics(text):
    result = {}
    for line in text.splitlines():
        match = re.fullmatch(r"net_accel_dns_([a-z_]+) ([0-9.eE+-]+)", line)
        if match:
            value = float(match[2])
            if not math.isfinite(value) or value < 0:
                raise ValueError("invalid metrics value")
            result[match[1]] = value
    required = {"received_total", "hits_total", "failures_total", "processing_seconds_count",
                "processing_seconds_sum", "job_queue_depth", "reply_queue_depth"}
    if not required <= result.keys():
        raise ValueError("incomplete DNS metrics")
    return result


def snapshot(services, port=19091):
    result = {"time": time.time(), "services": {}, "daily_service": "unknown", "metrics": None, "error": None}
    try:
        result["services"] = services.status()
        result["daily_service"] = services.daily_status()
    except (OSError, RuntimeError, subprocess.SubprocessError):
        pass
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(f"http://127.0.0.1:{port}/metrics", timeout=1) as response:
            content = response.read(MAX_METRICS + 1)
        if len(content) > MAX_METRICS:
            raise ValueError("DNS metrics response is too large")
        result["metrics"] = parse_metrics(content.decode("ascii"))
    except (OSError, ValueError) as error:
        result["error"] = f"Metrics unavailable at 127.0.0.1:{port}: {error}"
    return result


def measurements(current, previous=None):
    m = current["metrics"]
    if m is None:
        return None
    rate = None
    if previous and previous.get("metrics"):
        elapsed = current["monotonic"] - previous["monotonic"]
        delta = m["received_total"] - previous["metrics"]["received_total"]
        # A restart resets the entire set of counters. Never report a negative
        # rate or combine samples from workers with different lifetimes.
        reset = any(m.get(key, 0) < previous["metrics"].get(key, 0)
                    for key in ("received_total", "hits_total", "processing_seconds_count"))
        if elapsed > 0 and delta >= 0 and not reset:
            rate = delta / elapsed
    return {"queries_per_second": rate,
            "cache_hit_percent": 100 * m["hits_total"] / m["received_total"] if m["received_total"] else None,
            "average_processing_ms": 1000 * m["processing_seconds_sum"] / m["processing_seconds_count"]
            if m["processing_seconds_count"] else None}


def render(current):
    lines = ["DNS BOOSTER  |  localhost", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(current["time"])), ""]
    daily = current.get('daily_service', 'unknown')
    lines.append(f"{'Daily DNS service':<22} {daily}")
    for label, unit in (("UDP resolver", "net-accel-dns.service"), ("TCP fallback", "net-accel-dns-tcp.service")):
        state = 'active (daily service)' if daily == 'active' else current['services'].get(unit, 'unknown')
        lines.append(f"{label:<22} {state}")
    m, values = current["metrics"], current["measurements"]
    if m is None:
        lines += ["", current["error"], "Check: systemctl status net-accel-dns", "Logs:  journalctl -u net-accel-dns -n 30"]
    else:
        def number(value, unit=""):
            return "—" if value is None else f"{value:.2f}{unit}"
        lines += ["", f"{'Queries / second':<22} {number(values['queries_per_second'])}",
                  f"{'Total queries':<22} {int(m['received_total']):,}",
                  f"{'Cache hits':<22} {int(m['hits_total']):,} ({number(values['cache_hit_percent'], '%')})",
                  f"{'Forwarded':<22} {int(m.get('forwarded_total', 0)):,}",
                  f"{'Average processing':<22} {number(values['average_processing_ms'], ' ms')}",
                  f"{'Upstream failures':<22} {int(m['failures_total']):,}",
                  f"{'Upstream timeouts':<22} {int(m.get('upstream_timeouts_total', 0)):,}",
                  f"{'Overloaded':<22} {int(m.get('overloaded_total', 0)):,}",
                  f"{'Work / reply queue':<22} {int(m['job_queue_depth'])} / {int(m['reply_queue_depth'])}",
                  "", "Totals and averages: current worker. Rate: since previous sample.",
                  "DNS processing only; browser caches and external Secure DNS affect traffic."]
        if m["received_total"] == 0:
            lines += ["No queries yet. Send traffic with: dnsctl check"]
    # Logs/network errors must not be able to send terminal control sequences.
    return "\n".join("".join(c if c >= ' ' else '?' for c in str(line)) for line in lines)


def monitor(services, port=19091, watch=False, interval=1.0, samples=None, json_output=False, output=None):
    output = sys.stdout if output is None else output
    previous, count, code = None, 0, 0
    interactive = watch and not json_output and output.isatty()
    try:
        if interactive:
            output.write("\033[?1049h\033[?25l")
            output.flush()
        while True:
            started = time.monotonic()
            current = snapshot(services, port)
            current["monotonic"] = time.monotonic()
            current["measurements"] = measurements(current, previous)
            code = 0 if current["metrics"] is not None else 1
            if json_output:
                output.write(json.dumps({k: v for k, v in current.items() if k != "monotonic"}) + "\n")
            else:
                if interactive:
                    output.write("\033[H\033[2J")
                elif count:
                    output.write("\n")
                output.write(render(current) + ("\n\nCtrl+C to exit\n" if interactive else "\n"))
            output.flush()
            previous, count = current, count + 1
            if not watch or samples is not None and count >= samples:
                return code
            time.sleep(max(0, interval - (time.monotonic() - started)))
    except KeyboardInterrupt:
        return 0
    finally:
        if interactive:
            output.write("\033[?25h\033[?1049l")
            output.flush()
