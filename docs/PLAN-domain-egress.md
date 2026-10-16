# Plan: domain-based egress rules for Whalewall (IPv4 and IPv6)

Status: plan only, no code written. Branch: `claude/docker-egress-firewall-plan-t1iv5h`.

Decisions taken (from review): full IPv6 support is in scope; `*.example.com` never matches `example.com`; nested subdomains are matched by a separate `**.` syntax; the feature is opt-in via a `-dns` flag.

## 1. Findings from the code (answers to the handoff's "to verify" list)

| Question | Answer | Evidence |
|---|---|---|
| Hostnames in rules today? | No. `ips` is `[]addrOrRange`, which only parses IP, CIDR or `a-b` range. Labels are decoded with `KnownFields(true)`, so an unknown `domains` key is a hard error. | `config.go:124-153`, `create.go:97-98` |
| Default policy for `whalewall.enabled: true`? | Drop. Each container gets its own chain ending in a drop rule; no rules label means drop-all. | `create.go:242-246,281-283` |
| How are containers identified? | IPv4 `saddr`/`daddr` lookup in verdict map `whalewall-container-addrs`, jumping to a per-container chain. | `base.go:32-38,84-202`, `create.go:134-151` |
| IPv6 today? | Not supported. Only `TableFamilyIPv4` `filter` is managed; addresses go through `As4()`; header offsets 12/16 are hard-coded; the DB `addrs` key is the raw address bytes. | `base.go:23-26,45-79`, `create.go:114`, `database/schema.sql` |
| `network_mode: host`? | Rejected with an error. | `create.go:85-89` |
| Hooks | Jumps from `DOCKER-USER`, `INPUT`, `OUTPUT` into chain `whalewall`. No `nat` table is touched, so DNAT is new surface. | `base.go:136-181` |
| Sandbox | Binary runs under landlock and a gVisor seccomp allowlist; a DNS listener needs `listen`, `accept4`, `recvfrom`, `sendto`, `recvmsg`, `sendmsg`, `setsockopt` added (argument-constrained where possible). | `cmd/whalewall/seccomp.go` |
| Test harness | `whalewall_test.go`: `TestRuleCreation` uses `mock-nftables.go` and `mock-docker.go`; `TestIntegration` needs root, Docker and the internet. | `whalewall_test.go`, `.github/workflows/test.yml` |

To verify on a real host in Phase 0:
- Embedded Docker DNS (127.0.0.11) forwards from the container netns, so PREROUTING sees the container IP (for both v4 and v6 upstream paths).
- Whether the container chain lets established connections survive set-element expiry (decides TTL semantics).
- Docker's IPv6 filtering: `ip6tables` support (stable from Docker 28; needs `"ipv6": true, "ip6tables": true` in `daemon.json`). Confirm an `ip6 filter DOCKER-USER` chain exists and how published ports and the gateway behave on v6.

Environment note: in this sandbox the Docker CLI, compose and `nft` exist but no Docker daemon answers. Phase 0 checks whether `dockerd` can be started here; if not, e2e and screenshots come from a CI job (section 6.4).

## 2. Design

### 2.1 Rule schema
New field on output rules: `domains: [..]`.
- Mutually exclusive with `ips` and `container`.
- Requires `proto` and `dst_ports`, like every other rule.
- Applies to both address families; no per-family option needed.

Entry syntax (names are lower-cased, IDNA-normalised, trailing dot stripped):

| Entry | Matches | Does not match |
|---|---|---|
| `api.example.com` | exactly that name | any other name |
| `*.example.com` | exactly one label below: `a.example.com` | `example.com`, `a.b.example.com` |
| `**.example.com` | one or more labels, any depth: `a.example.com`, `a.b.c.example.com` | `example.com` |

To allow the apex and everything beneath it, list both `example.com` and `**.example.com`. `*` / `**` are valid only as the entire first label; `a.*.com`, `*a.com`, bare `*`, `**` and empty labels are rejected. (Alternative considered: a rule-level `nested: true` option; rejected because a per-entry syntax lets one rule mix both behaviours.)

```yaml
whalewall.rules: |
  output:
    - domains: ["api.github.com", "*.githubusercontent.com", "**.cdn.example.net"]
      proto: tcp
      dst_ports: [443]
```

### 2.2 `-dns` flag and related options
- `-dns` (default off): enables the resolver, the NAT tables and domain rules. With it off, behaviour is byte-for-byte unchanged for existing users.
- If a container has `domains` rules while `-dns` is off, rule creation fails for that container with a clear error and the container stays fully isolated (fail closed). It is never silently treated as allow-all.
- Supporting flags (only meaningful with `-dns`): `-dns-port` (default 5353), `-dns-upstream` (default: host resolvers from `/etc/resolv.conf`, v4 or v6), `-dns-min-ttl` (default 30s), `-dns-grace` (default 5s).

### 2.3 Resolver (`dns/` package, `github.com/miekg/dns`)
- UDP and TCP, listening on the gateway addresses of managed networks (v4 and, where present, v6) rather than a wildcard, so unmanaged networks never reach it. Listener set is reconciled on container create/die.
- Forwards allowed queries to the upstream; random source port and 0x20 case randomisation; truncated UDP answers retried over TCP.
- Source address -> container policy via an in-memory map owned by the rule manager. Unknown source -> `REFUSED` (default deny).
- Denied name -> `NXDOMAIN`, logged with container name (covers the CVE-2026-12039 class: the resolver enforces policy, not only the HTTP layer).
- Allowed name: forward, then for every A and AAAA record in the answer (all CNAME hops; only the QNAME is policy-checked) add the address to the right-family set with timeout `max(TTL, min_ttl) + grace`, and only then write the reply, so the first connection cannot race the rule.
- AAAA handling: if the container has no IPv6 address, AAAA gets an empty NOERROR (clients fall back to A); otherwise it is answered and enforced normally.

### 2.4 Interception (NAT)
- New tables `ip whalewall-nat` and `ip6 whalewall-nat`, chain `prerouting` (hook prerouting, priority -110, before Docker's own NAT).
- One rule per managed container address and per transport: `<family> saddr <cont> udp|tcp dport 53 dnat to <gateway>:<dns-port>`, using the container network's v4 or v6 gateway from Docker inspect.
- IPv6 NAT66 `dnat` requires the kernel's IPv6 NAT support (standard since 3.7); Phase 0 confirms.
- Everything else leaving port 53/853 is already dropped by the default drop. Documented caveat: an existing rule like `proto: tcp, dst_ports: [443]` with no `ips` allows any IP and defeats domain filtering; the validator logs a warning when such a rule is combined with `domains` rules.

### 2.5 IPv6 support in the firewall core
This is the larger refactor and applies to existing rule types too (`ips`, `container`, `mapped_ports`), not only domains.
- **Tables:** keep Docker's per-family layout. Add `ip6 filter` alongside `ip filter` (not `inet`, so Docker's existing `DOCKER-USER`, `INPUT`, `OUTPUT` chains are reused and existing installs are untouched). `createBaseRules` runs once per family with a `family` parameter; chain `whalewall`, jump rules and a second verdict map `whalewall-container-addrs6` (`ipv6_addr`) are created in the v6 table.
- **Per-container chains:** one chain per family (same name in each table). Chain, set and rule builders take a `family` value that selects address length, header offsets (v4 saddr 12 / daddr 16; v6 saddr 8 / daddr 24) and set key type. `createIPExprs` already works from `netip.Addr`, so v6 CIDRs and ranges in `ips` apply to the v6 chain; an `ips` entry only produces rules in its own family.
- **Protocol match:** use `meta l4proto` and transport-header payload bases so IPv6 extension headers do not break port matching.
- **Required ICMPv6 allowances in v6 container chains:** neighbour/router discovery (types 133-137) and packet-too-big (type 2), otherwise a default-drop chain breaks v6 connectivity entirely. Added as base rules ahead of the drop rule; no echo or other types.
- **Database:** `addrs.addr` is already a BLOB; store 4- or 16-byte keys and replace every `As4()` use with a helper returning `(family, bytes)`. No schema migration needed; add a test that a DB written by the old version still loads.
- **`mapped_ports`:** parity on v6 where Docker publishes v6 ports (Phase 0 confirms mechanism); otherwise explicitly documented as v4-only and rejected with an error if requested for a v6-only container.
- **Fail closed:** if a managed container has an IPv6 address but the `ip6` base rules cannot be created (e.g. Docker `ip6tables` disabled), the container's rule creation errors loudly rather than leaving v6 open. If no managed container uses v6, the absence of `ip6 filter DOCKER-USER` is only an info log.
- **Per-domain sets:** each domain rule gets one timed set per family: `ww-<id12>-<idx>-4` (`ipv4_addr`) and `ww-<id12>-<idx>-6` (`ipv6_addr`), referenced by `ip daddr @set` / `ip6 daddr @set` accept rules in the matching container chain. A resolver-reachability rule (`<family> daddr <gateway> udp|tcp dport <dns-port> accept`) is added only for containers with domain rules.

### 2.6 Lifecycle
- On `die`: remove NAT rules and the resolver mapping first, then the existing chain and set-element teardown (an IP cannot be reassigned while a stale mapping exists); chains deletion drops their sets.
- On daemon start: `syncContainers` rebuilds mappings from labels; existing sets are kept (idempotent `AddSet`, EEXIST ignored) so live allowances survive a restart; `cleanupRules` also removes orphaned `ww-*` sets and NAT rules in both families.
- Start-up race (container starts before its rules exist) is unchanged: its first DNS query may be `REFUSED` and retried.

### 2.7 Known limitations (documented in README)
- Shared CDN IPs: allowing a domain opens that IP for all names on it; SNI inspection is out of scope.
- Wildcard parents allow DNS tunnelling via subdomain labels to the allowed zone; an optional label-length/rate cap is a stretch item.
- Docker socket: README recommends a read-only socket proxy (events plus container inspect only).

## 3. Work breakdown

| Phase | Deliverable | Files |
|---|---|---|
| 0 | Feasibility spike: embedded DNS source IP, ct-established behaviour, Docker ip6tables behaviour, NAT66, dockerd in sandbox. Findings appended to this file. | notes only |
| 1 | IPv6 core: family-parameterised tables, maps, chains, offsets, ICMPv6 base rules, DB helpers, `mapped_ports` parity; no DNS yet. Existing tests stay green; new v6 rule tests. | `base.go`, `create.go`, `delete.go`, `sync.go`, `db.go`, `mock-nftables.go` |
| 2 | `domains` schema, parser, matcher (`*`, `**`), validator, `-dns` gating | `config.go`, new `domains.go`, `cmd/whalewall/main.go` |
| 3 | Resolver package with fake-upstream tests | new `dns/` |
| 4 | Domain rules in nftables: timed per-family sets, resolver feeder, NAT tables, resolver-reachability rules | `create.go`, `base.go`, `wrap.go`, `mock-nftables.go` |
| 5 | Lifecycle: mapping updates, restart reconcile, cleanup | `manager.go`, `sync.go`, `delete.go` |
| 6 | Seccomp/landlock, Dockerfile, README (labels, flags, limitations, Docker v6 requirements) | `cmd/whalewall/*`, `Dockerfile`, `README.md` |
| 7 | E2E harness, evidence, CI workflow | `e2e/`, `docs/evidence/`, `.github/workflows/e2e.yml` |

Each phase is its own commit; lint, race tests, vuln and codeql must stay green.

## 4. Test plan

### 4.1 Unit (no root)
- `domains_test.go`, table-driven. Syntax: valid and invalid forms (`*.a.com`, `**.a.com`, `a.*.com`, `*a.com`, `*`, `**`, `*.`, uppercase, IDN, trailing dot, empty label, 63/253-length limits). Matching: exact; `*` matches one label only (`a.example.com` yes, `a.b.example.com` no, `example.com` no); `**` matches depth 1, 2 and 5 but not the apex; case-insensitivity; near-miss `evilexample.com` and `example.com.evil.net`; wildcard and exact in the same rule.
- `config_test.go`: `domains` with `ips`/`container` rejected; missing `proto`/`dst_ports` rejected; unknown keys still rejected; `domains` with `-dns` off yields the fail-closed error; v6 `ips` entries, CIDRs and ranges parse and are family-split.
- `dns/resolver_test.go`, in-process fake upstream on localhost (v4 and v6 listeners): allowed A and AAAA, denied NXDOMAIN (upstream query count stays 0), CNAME chain inserts every hop's addresses, AAAA empty for v4-only container, unknown source REFUSED, TCP and truncation retry, EDNS pass-through, upstream timeout -> SERVFAIL, TTL clamping, 0x20 handling, set populated before reply (fake feeder asserts ordering), per-family set selection.

### 4.2 Rule generation (mock nftables, extending `TestRuleCreation`)
Golden comparisons for: v4-only, v6-only and dual-stack containers (correct offsets 12/16 vs 8/24, key types, `meta l4proto`); ICMPv6 ND and PTB allowances present only in v6 chains; single and multiple domain rules; domain plus plain-IP mix; container without domain rules (no NAT, no reachability rule); idempotent re-creation; cancel mid-creation cleans sets and NAT in both families; delete removes NAT, sets, chains; old-format DB loads.

### 4.3 Integration (root, real Docker/nftables; extends `TestIntegration`)
Deterministic and offline: a compose stack under `testdata/` with dual-stack user networks (`enable_ipv6`, `fd00:` ULA subnet), a fake authoritative DNS upstream serving zone `corp.test` over v4 and v6, `web-a` and `web-b` with fixed v4 and v6 addresses, and managed clients. Docker daemon configured with `ipv6` and `ip6tables`. Covers wildcard semantics, CNAMEs, TTL expiry (zone TTL 2s, `min_ttl` 0 in test), IP reuse for v4 and v6, daemon restart, two clients with different policies, unmanaged container unaffected, `-dns` off behaviour. `-binary-tests` and `-container-tests` modes also run the new tests so landlock/seccomp cover the resolver.

### 4.4 Security assertions folded into tests
- Denied names never reach the upstream (fake upstream counter) and each denial is logged with the container name.
- `dig @8.8.8.8`, `dig +tcp @8.8.8.8`, `dig @2001:4860:4860::8888`, DoT to 1.1.1.1:853 and `[2606:4700:4700::1111]:853`, and `dig @127.0.0.11` never reach a real upstream.
- Managed containers reach only the resolver port on the gateway; other gateway ports stay dropped on both families.
- A v6 address on a managed container with v6 base rules unavailable fails closed.

## 5. Evidence approach
Features are network behaviour, so screenshots are rendered terminal sessions, not GUI captures. `e2e/run.sh` runs each scenario against real Docker and whalewall and writes `e2e/out/NN-name.log` (command, output, expectation, PASS/FAIL). `e2e/render.mjs` turns each log into styled HTML. Playwright with the pre-installed Chromium (`/opt/pw-browsers`) screenshots each page to `docs/evidence/NN-name.png` and builds `docs/evidence/INDEX.md`. Evidence is generated by the run, never hand-written, and the script exits non-zero if any scenario fails.

## 6. End-to-end scenarios (one screenshot each)

| # | Feature | Scenario | Expected shown |
|---|---|---|---|
| 01 | Schema validation | Invalid `domains` (`a.*.com`, `domains`+`ips`, no `dst_ports`) | whalewall log shows validation errors; container fully isolated |
| 02 | `-dns` flag | `domains` label with whalewall started without `-dns`, then with `-dns` | first run: fail-closed error, no connectivity; second: works |
| 03 | Full isolation (v4+v6) | Managed client, no domains | curl to web-a over v4 and v6 and `dig` all fail |
| 04 | Exact domain | `a.corp.test` | curl succeeds over v4 and v6; `b.corp.test` NXDOMAIN; direct connect to web-b IPs times out |
| 05 | `*` single label | `*.corp.test` | `x.corp.test` ok; `x.y.corp.test` NXDOMAIN; apex `corp.test` NXDOMAIN |
| 06 | `**` nested | `**.corp.test` | `x`, `x.y`, `x.y.z.corp.test` ok; apex denied |
| 07 | Apex plus nested | `corp.test` and `**.corp.test` | apex and all depths ok |
| 08 | CNAME chain | `alias.corp.test` -> `a.corp.test` | allowed; `nft list set` shows both families' final addresses |
| 09 | Port/proto scoping | rule allows tcp/8080 | 8080 ok; 22 and udp fail on v4 and v6 |
| 10 | TTL expiry | zone TTL 2s | connect ok, after expiry a new connection fails, set element gone |
| 11 | DNS bypass v4 and v6 | direct, TCP, DoT, 127.0.0.11 | none reach a real upstream; fake-upstream counter unchanged for denied names |
| 12 | AAAA handling | v4-only vs dual-stack container | v4-only: empty NOERROR; dual-stack: AAAA answered and enforced |
| 13 | IPv6 core parity | existing rule types (`ips` v6 CIDR, `container`, `mapped_ports`) on dual-stack | behave as v4 equivalents; ND and PTB work, echo to gateway dropped |
| 14 | Per-container policy | client1 allows a, client2 allows b | each reaches only its own domain |
| 15 | Unmanaged container | no label | unaffected, DNS not intercepted |
| 16 | Die and IP reuse | stop client, start another on same v4/v6 IPs | no inherited allowances; ruleset shows sets/NAT removed |
| 17 | Daemon restart | restart whalewall mid-session | allowances retained, no duplicate rules, ruleset before/after |
| 18 | Fail closed on v6 | Docker `ip6tables` disabled, managed container with v6 | loud error and container not left open |
| 19 | Sandbox | built binary and container image (`-binary-tests`, `-container-tests`) | scenarios 04, 06, 11 pass; no seccomp kill in logs |
| 20 | Regression | existing `testdata/docker-compose.yml` ruleset with `-dns` off and on | identical results |
| 21 | Known limitation | direct connect to an allowed IP shared with another name | shown honestly, labelled "known limitation" |

### Where it runs
Phase 0 decides. If dockerd and nft work in this sandbox, scenarios and screenshots run here and PNGs are committed under `docs/evidence/`. Otherwise `.github/workflows/e2e.yml` (ubuntu runner, root, Docker, same as `test.yml`) runs `e2e/run.sh`, renders, and uploads the PNGs as a workflow artifact, with the run linked from the PR.

## 7. Risks
- Embedded DNS forwarding varies across Docker versions and rootless/userland-proxy setups; Phase 0 gates the design.
- Docker IPv6 filtering (`ip6tables`) is newer and less uniform than v4; if `DOCKER-USER` semantics differ, Phase 1 adapts the jump points. This is the largest schedule risk (Phase 1 is roughly as big as the DNS work).
- google/nftables v0.2.0 may lack some set-timeout, NAT or ICMPv6 expression support; fallback is a dependency bump.
- NAT66 availability depends on host kernel modules.
- Seccomp allowlist growth widens the sandbox slightly; syscalls are argument-constrained where possible.
