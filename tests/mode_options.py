"""Reject invalid mode combinations before touching network resources."""
import subprocess
import sys
runtime_error = "interface not found" if len(sys.argv) < 3 or sys.argv[2] == "ON" else "XDP support is disabled"

for options, message in [
    (["--forward-zone", "test=1.1.1.1", "--forward-zone", "TEST.=8.8.8.8"], "duplicate forward zone"),
    (["--forward-zone", ".=1.1.1.1"], "invalid forward zone"),
    (["--forward-zone", "bad..test=1.1.1.1"], "invalid forward zone"),
    (["--forward-zone", "*.test=1.1.1.1"], "ASCII DNS names"),
    (["--upstream-transport", "tls"], "upstream transport must be"),
    (["--listen-address", "0.0.0.0"], "unicast IPv4"),
    (["--listen-address", "192.0.2.1/24"], "IPv4 host"),
    (["--metrics-port", "53"], "metrics port must be"),
    (["--network-rate-limit", "192.0.2.0/24:0"], "budget rate must"),
    (["--reserve-client", "192.0.2.0/24:100"], "single IPv4 host"),
    (["--reserve-client", "192.0.2.1:100", "--rate-limit", "99"], "reserved rates exceed"),
    (["--run-as", "root"], "existing non-root user"),
    (["--allow-client", "192.0.2.1/33"], "allowed client must be"),
    (["--allow-client", "example.com"], "allowed client must be"),
    (["--rate-limit", "1000001"], "invalid numeric option"),
    (["--client-rate-limit", "-1"], "invalid numeric option"),
    (["--client-rate-limit", "1.5"], "invalid numeric option"),
    (["--allow-client", "192.0.2.1"] * 65, "at most 64"),
    (["--xdp-mode", "auto"], "XDP mode must be"),
    (["--xsk-mode", "auto"], "XSK mode must be"),
    (["--xsk-mode", "zero-copy"], "zero-copy requires"),
    (["--xdp-mode", "generic", "--xsk-mode", "zero-copy"], "zero-copy requires"),
]:
    result = subprocess.run([sys.argv[1], "unused0", *options], capture_output=True, text=True)
    assert result.returncode == 1 and message in result.stderr, result
for mode, xsk in [("generic", "copy"), ("native", "copy"), ("native", "zero-copy")]:
    result = subprocess.run([sys.argv[1], "unused0", "--xdp-mode", mode, "--xsk-mode", xsk], capture_output=True, text=True)
    assert result.returncode == 1 and runtime_error in result.stderr, result

result = subprocess.run([sys.argv[1], "unused0", "--allow-client", "192.0.2.0/24", "--allow-client", "198.51.100.7",
                         "--rate-limit", "10000", "--client-rate-limit", "100"], capture_output=True, text=True)
assert result.returncode == 1 and runtime_error in result.stderr, result

for args in [[], ["--bind", "0.0.0.0:53"], ["--bind", "192.0.2.1:53"], ["--workers", "0"],
             ["--queue", "0"], ["--upstream", "127.0.0.1:53"], ["--forward-zone", "test=127.0.0.1:53"]]:
    if not args:
        continue
    result = subprocess.run([sys.argv[1], "--mode", "socket", "--check-config", *args], capture_output=True, text=True)
    assert result.returncode == 1, result
result = subprocess.run([sys.argv[1], "--mode", "socket", "--check-config"], capture_output=True, text=True)
assert result.returncode == 0 and "Configuration valid" in result.stdout, result
