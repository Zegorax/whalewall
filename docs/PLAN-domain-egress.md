# Plan: domain-based egress rules for Whalewall

Status: plan only, no code written. Branch: `claude/docker-egress-firewall-plan-t1iv5h`.

## 1. Answers to the handoff's "to verify" questions (from reading the code)

| Question | Answer | Evidence |
|---|---|---|
| Does Whalewall accept hostnames in rules? | No. `ips` is `[]addrOrRange`, whose `UnmarshalText` only parses IP, CIDR or `a-b` range. Labels are decoded with `KnownFields(true)`, so an unknown `domains` key is a hard error today. | `config.go:124-153`, `create.go:97-98` |
| Default policy for `whalewall.enabled: true`? | Drop. Each container gets its own chain ending in a drop rule; a container with no `whalewall.rules` label gets drop-all. | `create.go:242-246`, `create.go:281-283` |
| How is a container identified? | IPv4 source/dest address looked up in verdict map `whalewall-container-addrs` (`ip saddr`/`ip daddr` -> jump to per-container chain). | `base.go:32-38,84-202`, `create.go:134-151` |
| IPv6? | Not supported at all. Only `TableFamilyIPv4` `filter` is managed and addresses are parsed with `As4()`. | `base.go:23-26`, `create.go:114` |
| `network_mode: host`? | Rejected with an error (single network named `host`). | `create.go:85-89` |
| Where do hooks live? | Jumps from `DOCKER-USER`, `INPUT`, `OUTPUT` into chain `whalewall`. No `nat` table is touched today, so DNAT is new surface. | `base.go:136-181` |
| Sandboxing | Binary runs under landlock and a gVisor seccomp allowlist (`cmd/whalewall/seccomp.go`). A DNS listener needs new syscalls (`listen`, `accept4`, `recvfrom`, `sendto`, `recvmsg`, `sendmsg`, `setsockopt`) added to the allowlist. | `cmd/whalewall/` |
| Test harness | `whalewall_test.go` (~3000 lines): `TestRuleCreation` uses `mock-nftables.go` and `mock-docker.go`; `TestIntegration` needs root, real Docker and the internet. | `whalewall_test.go`, `.github/workflows/test.yml` |

Still to verify on a real host (Phase 0): the embedded Docker DNS (127.0.0.11) forwards from the container netns so PREROUTING sees the container IP; the container chain's established/related handling (decides whether TTL expiry cuts live connections).

Environment note: in this sandbox the Docker CLI and compose exist but no Docker daemon answers, and nft is present. Phase 0 checks whether `dockerd` can be started here. If not, the e2e run and screenshots are produced by a CI job (section 6.4) instead.

## 2. Design (builds on handoff option B2, with decisions)

1. **Schema.** New field on an output rule: `domains: [..]`.
   - Mutually exclusive with `ips` and `container`.
   - Requires `proto` and `dst_ports`, same as every other rule.
   - Entry syntax: exact FQDN (`api.github.com`) or leading wildcard (`*.example.com`). `*.example.com` matches any depth below `example.com`, not the apex itself; list the apex separately.
   - Names are lower-cased, IDNA-normalised, trailing dot stripped. Reject `*` anywhere but the first label, empty labels, and bare `*`.
   - Example:
     ```yaml
     whalewall.rules: |
       output:
         - domains: ["api.github.com", "*.githubusercontent.com"]
           proto: tcp
           dst_ports: [443]
     ```
2. **Resolver** (`dns/` package, `github.com/miekg/dns`). UDP and TCP listener, forwards to upstream (`-dns-upstream`, default first nameserver of host `/etc/resolv.conf`). Opt-in via `-dns` flag so existing users see no change.
3. **Interception.** New nftables table `ip whalewall-nat`, chain `prerouting` (hook prerouting, priority -110, before Docker's own NAT). One rule per managed container address: `ip saddr <cont> udp|tcp dport 53 dnat to <gateway>:<dns-port>`. The gateway is the container's network gateway from Docker inspect, so the resolver is reachable without extra routing. The resolver listens on 0.0.0.0:<dns-port> but the filter table only lets managed containers reach it (see 5).
4. **Identity.** Resolver maps source IP -> container policy using an in-memory map owned by the rule manager, updated when rules are created/deleted. Unknown source -> `REFUSED` (default deny).
5. **Per-container decision.** Query name matched against the container's compiled domain matcher. Denied -> `NXDOMAIN`. In the container chain, a rule `ip daddr <gateway> udp|tcp dport <dns-port> accept` is added only when the container has domain rules.
6. **Dynamic sets.** One timeout-enabled set `ww-<id12>-<ruleIdx>` (type `ipv4_addr`) per domain rule, referenced by `ip daddr @set <proto> dport <ports> accept` in the container chain. For allowed answers the resolver adds each A record in the answer (following the whole CNAME chain; only the QNAME is policy-checked) with timeout `max(TTL, min_ttl) + grace`, and only then writes the response to the client, so the first connection cannot race the rule. Deleting the container chain also deletes its sets.
7. **IPv6 decision.** The firewall is IPv4-only, so for managed containers the resolver answers AAAA with empty NOERROR (clients fall back to A). Documented as a limitation; real IPv6 support is a separate project.
8. **Bypass blocking.** Port 53 from managed containers is always DNAT'd; everything else is already dropped by the default drop (DoT 853, DoH to non-allowed IPs). Documented caveat: a pre-existing rule such as `proto: tcp, dst_ports: [443]` with no `ips` allows any IP, which defeats domain filtering; the validator logs a warning when a container mixes such a rule with `domains` rules.
9. **Lifecycle.** On `die`: remove NAT rule and resolver mapping first, then the existing chain/set-element teardown (IP cannot be reassigned while a stale mapping exists). On daemon start: `syncContainers` rebuilds mappings from labels; existing sets are kept (idempotent `AddSet`, EEXIST ignored) so live allowances survive a restart; `cleanupRules` also removes orphaned `ww-*` sets and NAT rules.
10. **Known limitation (unchanged from the handoff).** Allowing a domain on a shared CDN IP opens that IP for all names on it. SNI inspection is out of scope here. Wildcard parents also allow DNS-tunnelling via subdomain labels to the allowed zone; documented, optional label-length/rate cap is a stretch item.
11. **Docker socket.** README gains a note recommending a read-only socket proxy (events + container inspect only).

## 3. Work breakdown

| Phase | Deliverable | Files |
|---|---|---|
| 0 | Feasibility spike: confirm 127.0.0.11 forwarding source IP, ct-established behaviour, dockerd availability in sandbox | none (notes appended to this file) |
| 1 | Schema, parser, validator, matcher | `config.go`, new `domains.go` |
| 2 | Resolver package with fake-upstream tests | new `dns/` |
| 3 | nftables: NAT table, per-rule timeout sets, resolver->set feeder, `firewallClient` interface additions and mock support | `base.go`, `create.go`, `delete.go`, `wrap.go`, `mock-nftables.go` |
| 4 | Lifecycle: mapping updates on create/die, restart reconcile, cleanup | `manager.go`, `sync.go`, `delete.go` |
| 5 | CLI flags, seccomp/landlock allowlist, Dockerfile, README | `cmd/whalewall/*`, `Dockerfile`, `README.md` |
| 6 | E2E harness + evidence (section 6) | `e2e/`, `.github/workflows/e2e.yml` |

Each phase is a separate commit; CI (lint, race tests, vuln, codeql) must stay green.

## 4. Test plan

### 4.1 Unit (no root, run everywhere)
- `domains_test.go`, table-driven: valid/invalid syntax (`*.a.com`, `a.*.com`, `*`, `*.`, uppercase, IDN, trailing dot, empty label); matcher cases (exact, wildcard depth 1 and 3, apex vs wildcard, case-insensitivity, near-miss `evilexample.com` vs `*.example.com`).
- `config_test.go`: `domains` with `ips`/`container` rejected; missing `proto`/`dst_ports` rejected; unknown keys still rejected.
- `dns/resolver_test.go` with an in-process fake upstream on localhost: allowed A answer, denied NXDOMAIN, CNAME chain (A records of every hop inserted), AAAA stripped, unknown source REFUSED, TCP and truncated-UDP retry, EDNS pass-through, upstream timeout -> SERVFAIL, TTL clamping, case randomisation (0x20) queries, set is populated before the response is written (fake feeder asserts ordering).

### 4.2 Rule generation (mock nftables, extends `TestRuleCreation`)
Golden comparison of generated rules for: single domain rule, multiple rules with different ports, rule mixing domains and plain IP rules, container with no domain rules (no NAT, no resolver accept rule), idempotent re-creation (`TestCreationIdempotency` style), cancel mid-creation cleans sets and NAT rules (`TestCancelingCreation` style), delete removes NAT, sets, chain.

### 4.3 Integration (root, real Docker/nftables; extends `TestIntegration`)
Deterministic, no internet: compose file under `testdata/` with a fake authoritative DNS upstream container (`corp.test` zone), `web-a` and `web-b` containers on fixed IPs, and managed clients. Tests: exact, wildcard, CNAME, TTL expiry (zone TTL 2s, `min_ttl` set to 0 in test), IP reuse (stop client, start another on the same IP, assert no inherited allowance), daemon restart (allowances retained, no duplicates), two clients with different policies, unmanaged container unaffected. `-binary-tests` and `-container-tests` modes also run the new tests so landlock/seccomp coverage includes the resolver.

## 5. Security checks folded into tests
- CVE-2026-12039 class: denied names never reach upstream (fake upstream counts queries; asserted 0) and every attempt is logged with container name.
- Direct `dig @8.8.8.8`, `dig +tcp @8.8.8.8`, DoT (`openssl s_client -connect 1.1.1.1:853`), and `dig @127.0.0.11` all either get answered by Whalewall's policy or time out; none reach the real upstream.
- Managed containers reach the resolver port only; other host ports on the gateway stay dropped.

## 6. End-to-end evidence (screenshots)

### 6.1 Approach
Features are network behaviour on a terminal, so screenshots are rendered terminal sessions, not GUI captures:
1. `e2e/run.sh` executes each scenario against real Docker and whalewall and writes `e2e/out/NN-name.log` (command, output, expected, PASS/FAIL).
2. `e2e/render.mjs` turns each log into a styled HTML page (green PASS / red FAIL).
3. Playwright with the pre-installed Chromium (`/opt/pw-browsers`) screenshots each page to `docs/evidence/NN-name.png`, and builds `docs/evidence/INDEX.md`.
Evidence is generated by the run, never hand-written; the script exits non-zero if any scenario fails, so a screenshot cannot show a pass that did not happen.

### 6.2 Feature to scenario matrix (one screenshot each)

| # | Feature | Scenario | Expected shown in screenshot |
|---|---|---|---|
| 01 | Label schema | Start container with invalid `domains` labels (wildcard mid-name, domains+ips) | whalewall log shows validation error; container stays fully isolated |
| 02 | Full isolation | Managed client with no allowed domains | `curl` to web-a and `dig` both fail |
| 03 | Exact domain allow | `domains: [a.corp.test]` | `curl a.corp.test` succeeds, `b.corp.test` NXDOMAIN, `curl` to web-b IP times out |
| 04 | Wildcard | `*.corp.test` | `x.corp.test` and `x.y.corp.test` succeed, `corp.test` apex and `corp.test.evil` denied |
| 05 | CNAME chain | `alias.corp.test` -> `a.corp.test` | allowed; `nft list set` shows the final A record |
| 06 | Port/proto scoping | Rule allows tcp/8080 only | 8080 succeeds, 22 and udp fail |
| 07 | TTL expiry | Zone TTL 2s | connect succeeds, after expiry new connection to the IP fails, set element gone |
| 08 | DNS bypass | `dig @8.8.8.8`, `+tcp`, DoT 853, `@127.0.0.11` | none reach real upstream; fake-upstream query counter unchanged for denied names |
| 09 | AAAA handling | `dig AAAA a.corp.test` | empty NOERROR |
| 10 | Per-container policy | client1 allows a, client2 allows b | each reaches only its own domain |
| 11 | Unmanaged container | container without label | unaffected, DNS not intercepted |
| 12 | Lifecycle: die and IP reuse | stop client, start new one on same IP | new container has no inherited allowances; `nft list ruleset` shows sets/NAT removed |
| 13 | Daemon restart | restart whalewall mid-session | allowances retained, no duplicate rules, `nft list ruleset` before/after |
| 14 | Landlock/seccomp | run built binary (`-binary-tests`) and container image | scenarios 03 and 08 pass under sandbox, no seccomp kill in logs |
| 15 | Documented limitation | direct connect to allowed IP reached via another name | shows the shared-IP behaviour honestly, labelled "known limitation" |

### 6.3 Regression evidence
Scenario 16 reruns the existing `testdata/docker-compose.yml` ruleset with the DNS feature disabled and with it enabled to show that rules without `domains` behave identically.

### 6.4 Where it runs
Phase 0 decides. If dockerd and nft work in this sandbox, the run and screenshots happen here and the PNGs are committed under `docs/evidence/`. Otherwise `.github/workflows/e2e.yml` (ubuntu runner, root, Docker present, same as `test.yml`) runs `e2e/run.sh`, renders, and uploads the PNGs as a workflow artifact, with the fork's Actions run linked from the PR.

## 7. Risks
- Embedded DNS forwarding behaviour differs across Docker versions and rootless/userland-proxy setups; Phase 0 gates the whole design.
- google/nftables v0.2.0 may lack some set-timeout or NAT expression support; fallback is a small bump of the dependency.
- Race between container start and rule creation already exists; first DNS query may get REFUSED and be retried by the client. Documented, not fixed.
- Seccomp allowlist growth widens the sandbox slightly; each added syscall is argument-constrained where possible.

## 8. Decisions needed from you
1. IPv6: accept "AAAA suppressed, IPv4 only" for this scope?
2. Wildcard semantics: `*.example.com` excludes the apex (plan) or includes it?
3. Opt-in `-dns` flag (plan) or on whenever any container has `domains`?
