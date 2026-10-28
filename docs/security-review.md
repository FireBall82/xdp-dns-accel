# Security review — 2026-10-28

The resolver has two packet adapters: a localhost UDP socket and optional
IPv4/UDP XDP acceleration. Both use the same parser, admission policy, worker
pool, and response cache. Unbound provides a separate localhost TCP fallback.
`dnsctl` monitors localhost metrics and manages services; daily mode temporarily
redirects NetworkManager DNS and saves recovery state before changing it.

## Fixed in this review

`restore_question` could copy an expanded compressed question over a shorter
encoded question. A crafted binary label containing a second name, followed by
a backward compression pointer, reproduced a heap buffer overflow under
AddressSanitizer: a 41-byte name was written at offset 12 in a 39-byte response.
This path requires a parsed client question and an upstream response with the
matching compressed question layout. Exploitability beyond the reproduced
out-of-bounds write was not assessed.

The function now checks that both question layouts have the space required for
the expanded name before restoring capitalization. Compressed layouts remain
intact, and transaction IDs are still restored. Resizing the packet would be
unsafe because it could invalidate compression offsets in later records.

The regression suite includes the reproducer. The DNS fuzzer now exercises
responses that echo query layouts as well as synthesized responses, and the
crafted compressed question is retained as a corpus seed.

The preceding readiness-check fix also rejects truncated replies, nonstandard
opcodes, the reserved header bit, and question counts other than one. These
checks protect service activation and restart decisions.

## Existing protections reviewed

- DNS parsing and upstream requests run after the worker drops its root
  identity and capabilities. The supervisor owns privileged XDP teardown.
- Process hardening disables core dumps and enables `no_new_privs`. Build
  checks verify PIE, RELRO, a non-executable stack, and stack protection.
- Upstream sockets use connected peers, randomized transaction IDs, matched
  questions, and deadlines. Cache keys include upstream endpoint and transport.
- Queues, coalesced followers, tracked clients, and cache storage have fixed
  bounds. Admission policy is applied before cache lookup.
- Shared cache attachment checks ownership, private permissions, layout, and
  version. Cache locks recover from a process dying while holding a lock.
- The socket adapter and metrics listener bind to localhost. Daily mode retains
  recovery state and refuses to overwrite externally changed runtime DNS rules.

## Deployment boundaries

XDP defaults allow all client addresses and disable rate limits. Configure
`--allow-client`, `--listen-address`, and rate budgets for the intended network;
the conventional resolver on bypass paths needs its own access policy.

Upstream DNS is ordinary UDP/TCP. This implementation does not add encrypted
transport or independently validate DNSSEC. Private forwarding rules and
upstream trust therefore remain part of deployment configuration.

This was a source review with targeted regression, sanitizer, and fuzz testing.
It does not establish that every vulnerability is absent. The installed host
services were not replaced or restarted by this review.

## Validation

- Normal build: all 10 CTest tests passed.
- AddressSanitizer/UBSan build: all 10 CTest tests passed after the fix.
- Clang fuzz build: all 12 CTest tests passed.
- DNS and packet fuzzers: 100,000 iterations each, with no reported failure.
- Isolated NixOS XDP check: generic and native packet tests passed.

The direct host XDP smoke test could not run without a sudo password; the NixOS
VM check provided the privileged packet validation in an isolated environment.
