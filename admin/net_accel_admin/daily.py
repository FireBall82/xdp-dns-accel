"""Standalone, reversible NetworkManager DNS integration; never edits /etc/nixos."""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import time

from .config import (DEFAULTS, atomic_write, daemon_arguments, domain_name,
                     load_routing, read_json, unbound_configuration, validate, write_json)
from .control import dns_probe

STATE = Path('/var/lib/net-accel-dns')
RUNTIME = Path('/run/net-accel-daily')
GENERATOR = Path('/usr/local/lib/systemd/system-generators/net-accel-dns-daily')
GCROOT = Path('/nix/var/nix/gcroots/net-accel-dns-daily')
NM_CONFIG = Path('/run/NetworkManager/conf.d/90-net-accel-dns.conf')
UNIT = 'net-accel-dns-daily.service'
LEGACY = ('net-accel-dns.service', 'net-accel-dns-tcp.service', 'net-accel-dns-prepare.service',
          'net-accel-dns-web.service', 'net-accel-dns-admin.service')


def run(command, timeout=20):
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout or 'command failed')[-2000:].strip())
    return result.stdout.strip()


def active(systemctl, unit):
    return subprocess.run([systemctl, 'is-active', '--quiet', unit], capture_output=True, timeout=5).returncode == 0


@contextmanager
def install_lock():
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (STATE / 'daily-install.lock').open('a') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def preflight(args):
    if not active(args.systemctl, 'NetworkManager.service'):
        raise ValueError('Daily mode requires NetworkManager on this machine')
    if active(args.systemctl, 'systemd-resolved.service'):
        raise ValueError('Standalone daily mode currently supports NetworkManager with its default DNS plugin; systemd-resolved is already active')
    run([args.nmcli, 'general', 'status'])


def stop_daily(args):
    try:
        run([args.systemctl, 'stop', UNIT], timeout=60)
    except RuntimeError:
        if active(args.systemctl, UNIT):
            raise


def install(args, enable):
    with install_lock():
        record = STATE / 'daily-install.json'
        if not enable:
            if not record.exists():
                print('Daily DNS is not enabled')
                return
            saved = read_json(record)
            stop_daily(args)
            restore(args)
            if GENERATOR.is_symlink() and str(GENERATOR.resolve()) == saved['generator']:
                GENERATOR.unlink()
            elif GENERATOR.exists() or GENERATOR.is_symlink():
                raise RuntimeError('Daily generator was changed externally; refusing to remove it')
            run([args.systemctl, 'daemon-reload'])
            if saved['previous_units']:
                run([args.systemctl, 'start', *saved['previous_units']], timeout=60)
            if GCROOT.is_symlink() and str(GCROOT.resolve()) == saved['package']:
                GCROOT.unlink()
            record.unlink()
            print('Daily DNS disabled; previous DNS management restored')
            return
        preflight(args)
        prefix = Path(args.daemon).resolve().parent.parent
        if record.exists():
            if read_json(record)['package'] != str(prefix):
                raise ValueError('Another package version is installed; run dnsctl disable before enabling this version')
            if active(args.systemctl, UNIT):
                print('Daily DNS is already enabled; use dnsctl watch')
                return
            run([args.systemctl, 'reset-failed', UNIT])
            run([args.systemctl, 'start', UNIT], timeout=90)
            return
        generator = prefix / 'libexec/net_accel_dns/net-accel-dns-generator'
        if not generator.is_file():
            raise ValueError('Build the installed package first: nix build path:.#default --out-link result; then sudo ./result/bin/dnsctl enable')
        if GENERATOR.exists() or GENERATOR.is_symlink():
            raise ValueError('A daily DNS generator is already installed without an ownership record')
        if GCROOT.exists() or GCROOT.is_symlink():
            raise ValueError('The daily DNS GC root is already in use')
        previous = [unit for unit in LEGACY[:3] if active(args.systemctl, unit)]
        saved = {'version': 1, 'package': str(prefix), 'generator': str(generator), 'previous_units': previous}
        if not (STATE / 'settings.json').exists():
            write_json(STATE / 'settings.json', DEFAULTS)
        write_json(record, saved)
        try:
            if str(prefix).startswith('/nix/store/'):
                GCROOT.parent.mkdir(parents=True, exist_ok=True)
                GCROOT.symlink_to(prefix)
            GENERATOR.parent.mkdir(parents=True, exist_ok=True)
            GENERATOR.symlink_to(generator)
            # Stop the old version before the generator masks it. The standalone
            # service owns both sockets and replaces any old web/control helpers.
            running = [unit for unit in LEGACY if active(args.systemctl, unit)]
            if running:
                run([args.systemctl, 'stop', *running], timeout=60)
            run([args.systemctl, 'daemon-reload'])
            run([args.systemctl, 'reset-failed', UNIT])
            run([args.systemctl, 'start', UNIT], timeout=90)
        except BaseException:
            # Retain the record if recovery itself fails, so disable can retry.
            stop_daily(args)
            restore(args)
            GENERATOR.unlink(missing_ok=True)
            run([args.systemctl, 'daemon-reload'])
            if previous:
                run([args.systemctl, 'start', *previous], timeout=60)
            if GCROOT.is_symlink() and GCROOT.resolve() == prefix:
                GCROOT.unlink()
            record.unlink()
            raise
        print('Daily DNS enabled and starts at boot. Monitor with dnsctl watch')


def tailscale_state(args):
    if not active(args.systemctl, 'tailscaled.service'):
        return None, []
    import json
    prefs = json.loads(run([args.tailscale, 'debug', 'prefs']))
    if type(prefs.get('CorpDNS')) is not bool:
        raise ValueError('Cannot safely determine the current Tailscale DNS preference')
    status = json.loads(run([args.tailscale, 'status', '--json']))
    tailnet = status.get('CurrentTailnet') or {}
    suffix = tailnet.get('MagicDNSSuffix') or (status.get('Self') or {}).get('DNSName', '').rstrip('.').partition('.')[2]
    return prefs['CorpDNS'], [domain_name(suffix)] if suffix else []


def routing_for(routing, search_domains, tailscale):
    result = {**routing, 'system_dns': True,
              'search_domains': list(dict.fromkeys([*routing['search_domains'], *search_domains]))}
    if tailscale:
        names = ['ts.net', '0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa']
        names += [f'{index}.100.in-addr.arpa' for index in range(64, 128)]
        result['forward_zones'] = {**dict.fromkeys(names, '100.100.100.100:53'), **routing['forward_zones']}
    from .config import validate_routing
    return validate_routing(result)


def search_domains():
    result = []
    for line in Path('/etc/resolv.conf').read_text().splitlines():
        words = line.split('#', 1)[0].split()
        if words and words[0] in ('search', 'domain'):
            result.extend(domain_name(word) for word in words[1:])
    return result


def nm_configuration(domains):
    domains = [domain_name(domain) for domain in domains]
    return '# Managed at runtime by dnsctl enable; removed by dnsctl disable\n[global-dns]\nsearches=' + ';'.join(domains) + '\n\n[global-dns-domain-*]\nservers=127.0.0.1\n'


def restore(args):
    backup = STATE / 'daily-network.json'
    if not backup.exists():
        return
    saved = read_json(backup)
    if NM_CONFIG.exists():
        if NM_CONFIG.read_text() != saved['nm_configuration']:
            raise RuntimeError('The runtime DNS snippet changed externally; refusing to overwrite it')
        NM_CONFIG.unlink()
    run([args.nmcli, 'general', 'reload', 'conf,dns-rc'])
    if saved['tailscale_accept_dns'] is not None:
        run([args.tailscale, 'set', '--accept-dns=' + str(saved['tailscale_accept_dns']).lower()])
    backup.unlink()


def notify_ready():
    address = os.environ.get('NOTIFY_SOCKET')
    if address:
        if address.startswith('@'):
            address = '\0' + address[1:]
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as client:
            client.connect(address)
            client.sendall(b'READY=1\nSTATUS=Local UDP/TCP DNS ready; NetworkManager uses the accelerator')


def supervise(args):
    preflight(args)
    restore(args)  # Recover an interrupted previous activation before new changes.
    RUNTIME.mkdir(mode=0o755, parents=True, exist_ok=True)
    config = validate(read_json(STATE / 'settings.json'))
    accept_dns, tail_domains = tailscale_state(args)
    if accept_dns is not None and config['upstream'].split(':')[0] == '100.100.100.100':
        raise ValueError('Use an independent public upstream; Quad100 is reserved for private Tailscale routes in daily mode')
    routing = routing_for(load_routing(args.routing_config), [*search_domains(), *tail_domains], accept_dns is not None)
    text = nm_configuration(routing['search_domains'])
    if NM_CONFIG.exists() or NM_CONFIG.is_symlink():
        raise ValueError('A runtime DNS snippet already exists; refusing to replace it')
    unbound_file = RUNTIME / 'unbound.conf'
    atomic_write(unbound_file, unbound_configuration(config, routing=routing), 0o644)
    run([args.checkconf, str(unbound_file)])
    children, stopping = [], False

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    env = {key: value for key, value in os.environ.items() if key != 'NOTIFY_SOCKET'}
    try:
        children.append(subprocess.Popen([args.daemon, *daemon_arguments(config, routing=routing)], env=env))
        children.append(subprocess.Popen([args.unbound, '-d', '-c', str(unbound_file)], env=env))
        deadline = time.monotonic() + 15
        while True:
            if stopping or any(child.poll() is not None for child in children):
                raise RuntimeError('DNS worker stopped during startup')
            try:
                dns_probe()
                dns_probe(tcp=True)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise RuntimeError('Local DNS readiness failed; system DNS was not redirected')
                time.sleep(0.2)
        write_json(STATE / 'daily-network.json', {'version': 1, 'nm_configuration': text,
                                                 'tailscale_accept_dns': accept_dns})
        if accept_dns is not None:
            run([args.tailscale, 'set', '--accept-dns=false'])
        NM_CONFIG.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(NM_CONFIG, text, 0o644)
        run([args.nmcli, 'general', 'reload', 'conf,dns-rc'])
        # Fail closed if a higher-priority manager/configuration ignored the
        # runtime override. Never claim daily activation based on local probes.
        servers = [line.split()[1] for line in Path('/etc/resolv.conf').read_text().splitlines()
                   if line.split()[:1] == ['nameserver'] and len(line.split()) >= 2]
        if servers != ['127.0.0.1']:
            raise RuntimeError('NetworkManager did not select localhost DNS; previous DNS will be restored')
        notify_ready()
        print('Daily DNS active: NetworkManager -> 127.0.0.1; private routes preserved', flush=True)
        while not stopping:
            if any(child.poll() is not None for child in children):
                raise RuntimeError('A DNS worker exited; restoring normal DNS before restart')
            time.sleep(0.2)
    finally:
        try:
            restore(args)
        finally:
            for child in reversed(children):
                if child.poll() is None:
                    child.terminate()
            for child in children:
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()


def generate(early, template):
    early = Path(early)
    early.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(template, early / UNIT)
    wants = early / 'multi-user.target.wants'
    wants.mkdir(exist_ok=True)
    (wants / UNIT).symlink_to('../' + UNIT)
    for unit in LEGACY:
        (early / unit).symlink_to('/dev/null')
