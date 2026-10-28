# Local DNS and terminal monitor

`dnsctl` replaces the website. It reads performance counters from
`127.0.0.1:19091`, reports UDP/TCP service health, and runs test lookups.
There is no access code, web settings page, or administration HTTP server.
Monitoring does not need root and does not change your DNS or NixOS configuration.

## Use it now

From this checkout:

```sh
nix develop --command cmake -S . -B build
nix develop --command cmake --build build -j2
./build/dnsctl watch
```

Leave the monitor open and send a few queries in another terminal:

```sh
./build/dnsctl check
dig @127.0.0.1 example.com A
dig @127.0.0.1 example.com A
```

`check` probes example.com over UDP and TCP and prints each round-trip time.
The performance counters measure the C++ UDP worker. The dedicated TCP fallback
has its own cache and is not included in those counters.

Other views:

```sh
./build/dnsctl status
./build/dnsctl status --json
./build/dnsctl watch --interval 2
./build/dnsctl watch --json --samples 5
```

`dnsctl` without arguments shows one status snapshot. `watch` refreshes once per
second by default; Ctrl+C exits and restores the terminal. In pipes, it prints
ordinary text without terminal escape codes. JSON watch output is one object per
line. `--metrics-port PORT` selects another localhost worker's metrics listener.
An unavailable worker produces an actionable message and a nonzero exit status;
watch keeps retrying. Counter resets after a worker restart reset the rate sample.

## What the numbers mean

- Queries/second is the change since the previous sample; a single snapshot has
  no rate yet.
- Total queries, cache hits, failures and timeouts are totals for the current
  worker's lifetime. They reset when the worker restarts.
- Cache-hit percentage uses hits divided by received queries. With no traffic,
  the percentage and average processing time show a dash.
- Average processing time runs from accepting a query until its response is
  queued. It includes cache hits and upstream requests, and excludes later
  network delivery and browser page loading.
- Queue depths show pending jobs and replies; overload counts rejected work.

These measurements show DNS behavior, not a measured improvement in web-page
loading speed. Browser/OS caches reduce traffic, and external Secure DNS providers
can bypass the local resolver. Explicit `dig @127.0.0.1` tests always target it.

## Set up daily browsing on this NixOS machine

Build the package, enable the standalone service, and check it:

```sh
nix build path:.#default --out-link result
sudo ./result/bin/dnsctl enable
./result/bin/dnsctl check
./result/bin/dnsctl watch
```

`enable` needs root to install the service and switch system DNS. Monitoring and
checks do not. The standalone integration supports NetworkManager's default DNS
plugin, including the resolvconf setup used on this machine. It refuses an active
systemd-resolved deployment instead of silently replacing its routing.

The service starts at boot. Before changing DNS, it starts the C++ UDP worker and
Unbound TCP fallback and checks both protocols. It then applies a temporary
NetworkManager global DNS override pointing at `127.0.0.1`. A higher-priority
configuration that prevents activation causes a rollback. Tailscale MagicDNS and
reverse DNS use Quad100 through fixed private forwarding rules; search suffixes
are preserved. Private failures never retry against the public upstream.

The public upstream still comes from the existing service settings (default:
`1.1.1.1:53`). `enable` does not choose a different public DNS provider. Upstream
UDP/TCP is ordinary DNS, without DoH/DoT encryption.

Use ordinary system lookups to confirm browsing traffic can reach the worker:

```sh
getent ahostsv4 example.com
getent ahostsv4 host.your-tailnet.ts.net
```

Replace the example tailnet hostname with one from your own tailnet.
Open the browser and use its system DNS: turn off an explicitly selected external
Secure DNS/DNS-over-HTTPS provider. Browser caches can reduce the traffic visible
in the monitor. The package has no website or login.

Undo daily mode at any time:

```sh
sudo ./result/bin/dnsctl disable
```

Disabling restores NetworkManager's previous DNS policy and Tailscale's saved
`accept-dns` preference. It removes the startup helper and package GC root, and
restarts previously active legacy UDP/TCP units. The removed web and control
services remain stopped. A failed activation also restores the previous setup.
A worker failure restores normal system DNS before systemd retries the service.

To update the installed package, disable the current version, build the new
version, then enable it again. After switching tailnets, restart daily mode to
refresh short-name search suffixes with `sudo ./result/bin/dnsctl restart`.

No edits to `/etc/nixos/configuration.nix`, your flake, or NetworkManager connection
profiles are made. The standalone installation uses these separate files:

- `/usr/local/lib/systemd/system-generators/net-accel-dns-daily`: package-owned
  startup helper; generates the daily unit and masks legacy instances at runtime.
- `/nix/var/nix/gcroots/net-accel-dns-daily`: keeps the enabled package available.
- `/var/lib/net-accel-dns/daily-install.json` and `daily-network.json`: ownership
  and recovery records, readable only by root.
- `/run/NetworkManager/conf.d/90-net-accel-dns.conf`: temporary DNS override,
  removed on stop/disable; DHCP-supplied DNS applies again afterward.

The existing NixOS module remains available to deployments that already use it;
this standalone startup path does not require importing it or rebuilding NixOS.

## Package and traditional services

The package includes `dnsctl`, the localhost UDP daemon, a dedicated Unbound TCP
fallback, and their systemd support. `packages.<system>.xdp` also includes the
optional XDP adapter. Building the package alone leaves system DNS unchanged.

For a traditional installation:

```sh
cmake -S . -B build-local -DENABLE_XDP=OFF
cmake --build build-local -j2
sudo cmake --install build-local
sudo dnsctl setup
```

Python 3.11+, systemd, and Unbound are required for service installation. Setup
creates the unprivileged DNS account and starts UDP/TCP on `127.0.0.1:53`.
It leaves system DNS unchanged. The native daemon also runs directly with
`--mode socket --bind 127.0.0.1:53 --metrics-port 19091` and the desired upstream.
Only one daemon can own the UDP and metrics endpoints.

Service settings remain in `/var/lib/net-accel-dns/settings.json`; they are not
exposed through the monitor. Fixed private forwarding rules remain shared by UDP
and TCP. `sudo dnsctl restart` validates the current configuration, restarts DNS,
checks UDP/TCP readiness, and recovers the previous configuration if startup
fails. No persistent privileged administration server runs.

If an older version's dashboard is still installed, stop its obsolete units:

```sh
sudo systemctl stop net-accel-dns-web.service net-accel-dns-admin.service
```

The CLI works with the existing worker's metrics, so DNS can keep running while
you switch to the terminal view. Removing source files does not stop an already
installed older web service. Do not launch a second daemon on the same ports.

## Diagnostics and checks

```sh
dnsctl doctor
systemctl status net-accel-dns net-accel-dns-tcp
journalctl -u net-accel-dns -u net-accel-dns-tcp -n 50
journalctl -u net-accel-dns-daily -n 50
ctest --test-dir build --output-on-failure
nix build path:.#checks.x86_64-linux.local-deployment
nix build path:.#checks.x86_64-linux.standalone-daily
```

The CLI tests use a real local metrics endpoint and a pseudo-terminal to verify
live updates, JSON, restarts, missing metrics, input validation, and clean Ctrl+C
exit. Deployment tests run the installed CLI as an unprivileged account and check
real UDP/TCP lookups and automatic worker recovery in an isolated VM. No test
changes the host's DNS configuration.

Standalone acceptance tests enable daily DNS without importing the NixOS module,
check ordinary public/private/short-name lookups and private TCP, reject an
unreachable upstream without changing DNS, recover from a killed worker, verify
boot activation, and disable to restore the previous DNS and Tailscale preference.
Tailscale is simulated in that offline VM; a real authenticated tailnet is not
required for the test.
