"""Terminal performance view and local DNS service commands."""
import argparse
import math
import time
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys

from .config import daemon_arguments, load_routing
from .control import Controller, Services, UNITS, dns_probe
from .monitor import monitor


def require_root():
    if os.geteuid() != 0:
        raise PermissionError("This command requires root")


def ensure_accounts():
    for user in ("net-accel-dns",):
        try:
            pwd.getpwnam(user)
        except KeyError:
            subprocess.run([shutil.which("useradd") or "/usr/sbin/useradd", "--system", "--user-group",
                            "--no-create-home", "--home-dir", "/", "--shell",
                            shutil.which("nologin") or "/usr/sbin/nologin", user], check=True)


def parser():
    result = argparse.ArgumentParser(description="Local DNS performance and service CLI", prog="dnsctl")
    result.add_argument("--state", default="/var/lib/net-accel-dns")
    result.add_argument("--runtime", default="/run/net-accel-dns")
    result.add_argument("--routing-config", default="/etc/net-accel-dns/routing.json")
    result.add_argument("--daemon", default=shutil.which("dns_daemon") or "/usr/local/bin/dns_daemon")
    result.add_argument("--systemctl", default=shutil.which("systemctl") or "/usr/bin/systemctl")
    result.add_argument("--checkconf", default=shutil.which("unbound-checkconf") or "/usr/sbin/unbound-checkconf")
    result.add_argument("--unbound", default=shutil.which("unbound") or "/usr/sbin/unbound")
    result.add_argument("--nmcli", default=shutil.which("nmcli") or "/run/current-system/sw/bin/nmcli")
    result.add_argument("--tailscale", default=shutil.which("tailscale") or "/run/current-system/sw/bin/tailscale")
    commands = result.add_subparsers(dest="command")
    result.set_defaults(command="status", json_output=False, metrics_port=19091)
    for name in ("prepare", "launch", "setup", "doctor", "check", "restart", "enable", "disable", "daily-run", "daily-restore"):
        commands.add_parser(name)
    for name in ("status", "watch"):
        view = commands.add_parser(name)
        view.add_argument("--json", action="store_true", dest="json_output")
        view.add_argument("--metrics-port", type=int, default=19091)
        if name == "watch":
            view.add_argument("--interval", type=float, default=1.0, metavar="SECONDS")
            view.add_argument("--samples", type=int, help="stop after this many updates")
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    services = Services(args.daemon, args.systemctl, args.checkconf)
    try:
        if args.command in ("status", "watch"):
            interval = getattr(args, "interval", 1.0)
            samples = getattr(args, "samples", None)
            if not 1 <= args.metrics_port <= 65535:
                raise ValueError("metrics port must be 1..65535")
            if not math.isfinite(interval) or not 0.2 <= interval <= 3600:
                raise ValueError("interval must be 0.2..3600 seconds")
            if samples is not None and samples < 1:
                raise ValueError("samples must be positive")
            return monitor(services, args.metrics_port, args.command == "watch", interval, samples, args.json_output)
        if args.command in ("doctor", "check"):
            if args.command == "doctor":
                monitor(services)
            for tcp in (False, True):
                started = time.monotonic()
                dns_probe(tcp=tcp)
                print(f"{'TCP' if tcp else 'UDP'} example.com via 127.0.0.1:53: OK ({1000 * (time.monotonic() - started):.2f} ms)")
            return 0
        require_root()
        if args.command in ("enable", "disable", "daily-run", "daily-restore"):
            from .daily import install, supervise, restore, UNIT
            if args.state != "/var/lib/net-accel-dns":
                raise ValueError("Daily service requires the standard state directory")
            if args.command in ("enable", "disable"):
                if args.command == "enable":
                    ensure_accounts()
                install(args, args.command == "enable")
            elif args.command == "daily-run":
                supervise(args)
            else:
                restore(args)
            return 0
        if args.command == "restart":
            from .daily import active, UNIT, STATE
            if active(args.systemctl, UNIT) or (STATE / "daily-install.json").exists():
                from .daily import run
                run([args.systemctl, "reset-failed", UNIT])
                run([args.systemctl, "restart", UNIT], timeout=90)
                print("Daily DNS restarted")
                return 0
        routing = load_routing(args.routing_config)
        controller = Controller(args.state, args.runtime, services, routing)
        if args.command == "setup":
            ensure_accounts()
            controller.prepare()
            services.validate(controller.config(), Path(args.runtime) / "unbound.conf", routing)
            services.run([args.systemctl, "daemon-reload"])
            services.run([args.systemctl, "enable", "--now", *UNITS])
            services.healthy()
            print("Local DNS is ready. Monitor with dnsctl watch. System DNS has not been changed.")
        elif args.command == "prepare":
            controller.prepare()
            services.validate(controller.config(), Path(args.runtime) / "unbound.conf", routing)
        elif args.command == "launch":
            config = controller.config()
            os.execv(args.daemon, [args.daemon, *daemon_arguments(config, routing=routing)])
        elif args.command == "restart":
            config = controller.config()
            controller.apply(config, config["revision"], restart=True)
            print("DNS restarted; UDP and TCP probes passed")
        return 0
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"dnsctl: {error}", file=sys.stderr)
        return 1
