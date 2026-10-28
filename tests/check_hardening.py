"""Verify the produced Linux ELF binary, rather than only its build flags."""
import re
import subprocess
import sys

readelf, binary = sys.argv[1:]
def inspect(*args):
    return subprocess.check_output([readelf, "--wide", *args, binary], text=True)

header = inspect("--file-header")
segments = inspect("--program-headers")
dynamic = inspect("--dynamic")
symbols = inspect("--symbols")
assert re.search(r"Type:\s+DYN\b", header) and re.search(r"FLAGS_1.*\bPIE\b", dynamic), "PIE missing"
assert "GNU_RELRO" in segments and re.search(r"BIND_NOW|FLAGS.*\bNOW\b", dynamic), "full RELRO missing"
stack = next(line for line in segments.splitlines() if "GNU_STACK" in line)
assert re.search(r"\bRW\b", stack) and not re.search(r"\bRWE\b", stack), "stack is executable"
assert "__stack_chk_fail" in symbols, "stack canary instrumentation missing"
print("Verified ELF hardening: PIE, full RELRO, non-executable stack, stack canary instrumentation")
