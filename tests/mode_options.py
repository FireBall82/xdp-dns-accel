"""Reject invalid mode combinations before touching network resources."""
import subprocess
import sys

for options, message in [
    (["--xdp-mode", "auto"], "XDP mode must be"),
    (["--xsk-mode", "auto"], "XSK mode must be"),
    (["--xsk-mode", "zero-copy"], "zero-copy requires"),
    (["--xdp-mode", "generic", "--xsk-mode", "zero-copy"], "zero-copy requires"),
]:
    result = subprocess.run([sys.argv[1], "unused0", *options], capture_output=True, text=True)
    assert result.returncode == 1 and message in result.stderr, result
for mode, xsk in [("generic", "copy"), ("native", "copy"), ("native", "zero-copy")]:
    result = subprocess.run([sys.argv[1], "unused0", "--xdp-mode", mode, "--xsk-mode", xsk], capture_output=True, text=True)
    assert result.returncode == 1 and "interface not found" in result.stderr, result
