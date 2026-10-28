"""Validated service settings and deterministic daemon/Unbound configuration."""
import ipaddress
import json
import os
import re
from pathlib import Path
import tempfile

DEFAULTS = {"version": 1, "revision": 1, "upstream": "1.1.1.1:53",
            "transport": "auto", "workers": 4, "rate_limit": 0, "client_rate_limit": 0}
CACHE_NAME = "/net_accel_dns_local_v3"
DNS_ADDRESS = ("127.0.0.1", 53)
METRICS_PORT = 19091
DEFAULT_ROUTING = {"version": 1, "system_dns": False, "search_domains": [], "forward_zones": {}}


def validate(value):
    if not isinstance(value, dict) or value.keys() != DEFAULTS.keys():
        raise ValueError("configuration must contain exactly the documented settings")
    value = dict(value)
    for key, low, high in (("version", 1, 1), ("revision", 1, 2**53 - 1), ("workers", 1, 64),
                           ("rate_limit", 0, 1000000), ("client_rate_limit", 0, 1000000)):
        if type(value[key]) is not int or not low <= value[key] <= high:
            raise ValueError(f"{key} must be an integer from {low} to {high}")
    if value["transport"] not in ("auto", "udp", "tcp"):
        raise ValueError("transport must be auto, udp or tcp")
    if not isinstance(value["upstream"], str):
        raise ValueError("upstream must be IPv4[:port]")
    parts = value["upstream"].split(":")
    if len(parts) not in (1, 2):
        raise ValueError("upstream must be IPv4[:port]")
    address = ipaddress.IPv4Address(parts[0])
    port_text = parts[1] if len(parts) == 2 else "53"
    if not port_text.isascii() or not port_text.isdecimal() or not 1 <= int(port_text) <= 65535:
        raise ValueError("upstream port must be 1..65535")
    if address.is_unspecified or address.is_multicast or str(address) == "255.255.255.255":
        raise ValueError("upstream must be unicast IPv4")
    if int(port_text) == 53 and str(address) in ("127.0.0.1", "127.0.0.53", "127.0.0.54"):
        raise ValueError("upstream cannot be the local listener or system DNS stub")
    value["upstream"] = f"{address}:{int(port_text)}"
    return value


def domain_name(value):
    if not isinstance(value, str) or not value.isascii():
        raise ValueError("DNS routing domains must be ASCII names")
    value = value[:-1] if value.endswith(".") else value
    if not value or len(value) > 253 or any(not re.fullmatch(r"[a-zA-Z0-9_-]{1,63}", label) for label in value.split(".")):
        raise ValueError("invalid DNS routing domain")
    return value.lower()


def validate_routing(value):
    if not isinstance(value, dict) or value.keys() != DEFAULT_ROUTING.keys():
        raise ValueError("invalid deployment routing configuration")
    if type(value["version"]) is not int or value["version"] != 1 or type(value["system_dns"]) is not bool:
        raise ValueError("invalid deployment routing version or mode")
    if not isinstance(value["search_domains"], list) or len(value["search_domains"]) > 16:
        raise ValueError("at most 16 DNS search domains")
    zones = value["forward_zones"]
    if not isinstance(zones, dict) or len(zones) > 128:
        raise ValueError("at most 128 forward zones")
    normalized = {}
    for domain, target in zones.items():
        domain = domain_name(domain)
        if domain in normalized:
            raise ValueError("duplicate forward zone")
        normalized[domain] = validate({**DEFAULTS, "upstream": target})["upstream"]
    return {"version": 1, "system_dns": value["system_dns"],
            "search_domains": [domain_name(name) for name in value["search_domains"]], "forward_zones": normalized}


def load_routing(path):
    try:
        return validate_routing(read_json(path))
    except FileNotFoundError:
        return validate_routing(DEFAULT_ROUTING)


def daemon_arguments(value, worker="net-accel-dns", routing=None):
    value = validate(value)
    routing = validate_routing(DEFAULT_ROUTING if routing is None else routing)
    result = ["--mode", "socket", "--bind", "127.0.0.1:53", "--run-as", worker,
            "--cache-name", CACHE_NAME, "--metrics-port", str(METRICS_PORT),
            "--upstream", value["upstream"], "--upstream-transport", value["transport"],
            "--workers", str(value["workers"]), "--rate-limit", str(value["rate_limit"]),
            "--client-rate-limit", str(value["client_rate_limit"])]
    for domain, target in sorted(routing["forward_zones"].items()):
        result.extend(["--forward-zone", f"{domain}={target}"])
    return result


def unbound_configuration(value, worker="net-accel-dns", routing=None):
    value = validate(value)
    routing = validate_routing(DEFAULT_ROUTING if routing is None else routing)
    zones = sorted(routing["forward_zones"].items())
    local_zones = "".join(f'    local-zone: "{domain}." transparent\n' for domain, _ in zones)
    host, port = value["upstream"].split(":")
    # TCP-only on the same address/port as the project's UDP listener. No recursion loop.
    return f'''server:
    interface: 127.0.0.1@53
    do-ip6: no
    do-udp: no
    do-tcp: yes
    do-not-query-localhost: no
    username: "{worker}"
    chroot: ""
    directory: "/"
    pidfile: ""
    use-syslog: no
    verbosity: 0
    access-control: 127.0.0.1/32 allow
    hide-identity: yes
    hide-version: yes
    module-config: "iterator"
{local_zones}forward-zone:
    name: "."
    forward-addr: {host}@{port}
    forward-tcp-upstream: yes
''' + "".join(f'''forward-zone:
    name: "{domain}."
    forward-addr: {target.replace(':', '@')}
    forward-tcp-upstream: yes
    forward-first: no
''' for domain, target in zones)


def read_json(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def atomic_write(path, data, mode=0o600):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_json(path, data, mode=0o600):
    atomic_write(path, json.dumps(data, indent=2) + "\n", mode)
