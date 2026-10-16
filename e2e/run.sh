#!/usr/bin/env bash
# End-to-end scenarios for domain based egress rules. Needs root, Docker,
# nft and Go. The scenarios run without internet access: DNS is served by
# a fake upstream (e2e/tools/fakedns) and "internet" hosts are containers
# on the same bridge.
#
#   e2e/run.sh            run all scenarios
#   e2e/run.sh 04 10      run only the given scenarios
#
# E2E_IPV6=1 uses a dual-stack network and runs the IPv6 scenarios; the
# Docker daemon must have ipv6 and ip6tables enabled.
set -u

cd "$(dirname "$0")/.."
ROOT=$PWD
OUT=${E2E_OUT:-$ROOT/e2e/out}
E2E_IPV6=${E2E_IPV6:-0}
WW=$ROOT/e2e/bin/whalewall
ONLY=" $* "

# shellcheck source=e2e/lib.sh
. "$ROOT/e2e/lib.sh"

want() { [ "$ONLY" = "  " ] || [[ "$ONLY" == *" $1 "* ]]; }

# ---------------------------------------------------------------- setup

setup() {
	rm -rf "$OUT"
	mkdir -p "$OUT/data" "$ROOT/e2e/bin"
	echo "building"
	CGO_ENABLED=0 go build -buildvcs=true -o "$WW" ./cmd/whalewall || exit 1
	CGO_ENABLED=0 go build -o "$ROOT/e2e/bin/fakedns" ./e2e/tools/fakedns || exit 1
	CGO_ENABLED=0 go build -o "$ROOT/e2e/bin/web" ./e2e/tools/web || exit 1
	docker image inspect "$IMG" >/dev/null 2>&1 || docker pull -q "$IMG" >/dev/null || exit 1

	cat >"$OUT/zone.txt" <<EOF
a.corp.test A 60 10.99.0.10
b.corp.test A 60 10.99.0.20
corp.test A 60 10.99.0.10
*.corp.test A 60 10.99.0.10
alias.corp.test CNAME 60 a.corp.test.
ttl.corp.test A 2 10.99.0.10
shared.corp.test A 60 10.99.0.10
other.test A 60 10.99.0.20
*.other.test A 60 10.99.0.20
EOF
	local listen=127.0.0.1:5300
	if [ "$E2E_IPV6" = 1 ]; then
		cat >>"$OUT/zone.txt" <<EOF
a.corp.test AAAA 60 fd00:99::10
b.corp.test AAAA 60 fd00:99::20
corp.test AAAA 60 fd00:99::10
*.corp.test AAAA 60 fd00:99::10
ttl.corp.test AAAA 2 fd00:99::10
EOF
	fi
	"$ROOT/e2e/bin/fakedns" -zone "$OUT/zone.txt" -log "$OUT/queries.log" -listen "$listen" >"$OUT/fakedns.out" 2>&1 &
	FAKEDNS_PID=$!

	docker network rm "$NET" >/dev/null 2>&1
	if [ "$E2E_IPV6" = 1 ]; then
		docker network create --ipv6 --subnet "$SUBNET4" --subnet "$SUBNET6" "$NET" >/dev/null || exit 1
	else
		docker network create --subnet "$SUBNET4" "$NET" >/dev/null || exit 1
	fi

	local name ip
	for spec in "web-a 10" "web-b 20"; do
		set -- $spec
		name=$1 ip=$2
		local args=(--network "$NET" --ip "10.99.0.$ip")
		[ "$E2E_IPV6" = 1 ] && args+=(--ip6 "fd00:99::$ip")
		docker rm -f "$name" >/dev/null 2>&1
		docker run -d --name "$name" "${args[@]}" -v "$ROOT/e2e/bin:/e2e:ro" --entrypoint /e2e/web "$IMG" -name "$name" >/dev/null || exit 1
	done

	RUN_START=$(date +%s)
	ww_start || exit 1
	sleep 1
}

teardown() {
	docker ps -aq --filter "network=$NET" | xargs -r docker rm -f >/dev/null 2>&1
	# give whalewall time to process the removal of containers
	[ -n "${WW_PID:-}" ] && sleep 2
	ww_stop
	[ -n "${FAKEDNS_PID:-}" ] && kill "$FAKEDNS_PID" 2>/dev/null
	docker network rm "$NET" >/dev/null 2>&1
	"$WW" -clear -d "$OUT/data" >/dev/null 2>&1
}
trap teardown EXIT

rules() { # rules <domains yaml list> [port]
	printf 'output:\n  - domains: %s\n    proto: tcp\n    dst_ports: [%s]\n' "$1" "${2:-8080}"
}

has_v6() { [ "$E2E_IPV6" = 1 ]; }

WEBA="http://10.99.0.10:8080/"
WEBB="http://10.99.0.20:8080/"

# ------------------------------------------------------------ scenarios

s01() {
	sc_begin 01 schema-validation "Invalid domain rules are rejected and the container is isolated"
	say "wildcards are only valid as the entire first label"
	start_client bad1 10.99.0.31 "$(rules '["a.*.corp.test"]')" --dns "$DUMMY_DNS"
	ww_log_excerpt 'invalid rules.*bad1' 1
	assert_contains "invalid rules" "whalewall rejects a mid-name wildcard"
	curl_in bad1 "$WEBA"
	assert_fail "container is isolated, web-a is unreachable"

	say "domains and ips are mutually exclusive"
	start_client bad2 10.99.0.32 'output:
  - domains: ["a.corp.test"]
    ips: ["10.99.0.10"]
    proto: tcp
    dst_ports: [8080]' --dns "$DUMMY_DNS"
	ww_log_excerpt 'invalid rules.*bad2' 1
	assert_contains "mutually exclusive" "whalewall rejects domains combined with ips"
	curl_in bad2 "$WEBA"
	assert_fail "container is isolated, web-a is unreachable"

	say "domains need proto and dst_ports"
	start_client bad3 10.99.0.33 'output:
  - domains: ["a.corp.test"]' --dns "$DUMMY_DNS"
	ww_log_excerpt 'invalid rules.*bad3' 1
	assert_contains "dst_ports" "whalewall rejects domains without ports"
	curl_in bad3 "$WEBA"
	assert_fail "container is isolated, web-a is unreachable"

	say "Docker's embedded resolver bypasses whalewall unless the container sets dns"
	start_client bad4 10.99.0.34 "$(rules '["a.corp.test"]')"
	ww_log_excerpt 'invalid rules.*bad4' 1
	assert_contains "dns" "whalewall refuses domain rules without the dns option"
	curl_in bad4 "$WEBA"
	assert_fail "container is isolated, web-a is unreachable"
	rm_containers bad1 bad2 bad3 bad4
	sc_end
}

s02() {
	sc_begin 02 dns-flag "Domain rules need the -dns flag"
	say "whalewall is restarted without -dns"
	ww_stop
	ww_start -dns-grace 1s
	start_client nodns 10.99.0.35 "$(rules '["a.corp.test"]')" --dns "$DUMMY_DNS"
	ww_log_excerpt 'invalid rules.*nodns' 1
	assert_contains "-dns flag" "whalewall explains that -dns is required"
	curl_in nodns "$WEBA"
	assert_fail "container is isolated, web-a is unreachable"
	hostsh "nft list tables | grep whalewall"
	assert_not_contains "whalewall-nat" "no DNS redirect table exists without -dns"
	rm_containers nodns
	sleep 0.5

	say "whalewall is restarted with -dns"
	ww_stop
	ww_start
	start_client withdns 10.99.0.36 "$(rules '["a.corp.test"]')" --dns "$DUMMY_DNS"
	curl_in withdns "http://a.corp.test:8080/"
	assert_contains "hello from web-a" "a.corp.test is reachable with -dns"
	hostsh "nft list tables | grep whalewall"
	assert_contains "whalewall-nat" "the DNS redirect table exists with -dns"
	rm_containers withdns
	sc_end
}

s03() {
	sc_begin 03 isolation "A managed container without domains is fully isolated"
	start_client iso 10.99.0.37 -
	curl_in iso "$WEBA"
	assert_fail "web-a is unreachable by IP"
	curl_in iso "$WEBB"
	assert_fail "web-b is unreachable by IP"
	if has_v6; then
		curl_in iso "-g -6 http://[fd00:99::10]:8080/"
		assert_fail "web-a is unreachable over IPv6"
	fi
	hostsh "nft list chain ip filter whalewall-iso-$(cid iso)"
	rm_containers iso
	sc_end
}

s04() {
	sc_begin 04 exact-domain "An exact domain is allowed, everything else is denied"
	start_client ex 10.99.0.41 "$(rules '["a.corp.test"]')" --dns "$DUMMY_DNS"
	cexec ex "nslookup a.corp.test"
	assert_contains "10.99.0.10" "a.corp.test resolves"
	curl_in ex "http://a.corp.test:8080/"
	assert_contains "hello from web-a" "a.corp.test is reachable over HTTP"
	cexec ex "nslookup b.corp.test"
	assert_contains "NXDOMAIN" "b.corp.test is denied with NXDOMAIN"
	curl_in ex "$WEBB"
	assert_fail "web-b is unreachable by IP"
	assert_eq "$(fakedns_queries b.corp.test)" 0 "the denied name never reached the upstream"
	set_elements ex 0
	assert_contains "10.99.0.10" "the resolved address is in the container's set"
	if has_v6; then
		curl_in ex "-g -6 http://a.corp.test:8080/"
		assert_contains "hello from web-a" "a.corp.test is reachable over IPv6"
		set_elements ex 0 6
		assert_contains "fd00:99::10" "the resolved IPv6 address is in the set"
	fi
	rm_containers ex
	sc_end
}

s05() {
	sc_begin 05 wildcard "*.corp.test matches exactly one label and never the apex"
	start_client wc 10.99.0.42 "$(rules '["*.corp.test"]')" --dns "$DUMMY_DNS"
	cexec wc "nslookup x.corp.test"
	assert_contains "10.99.0.10" "x.corp.test (one label) resolves"
	curl_in wc "http://x.corp.test:8080/"
	assert_contains "hello from web-a" "x.corp.test is reachable"
	cexec wc "nslookup x.y.corp.test"
	assert_contains "NXDOMAIN" "x.y.corp.test (two labels) is denied"
	cexec wc "nslookup corp.test"
	assert_contains "NXDOMAIN" "the apex corp.test is denied"
	cexec wc "nslookup evilcorp.test"
	assert_contains "NXDOMAIN" "evilcorp.test is denied"
	rm_containers wc
	sc_end
}

s06() {
	sc_begin 06 nested-wildcard "**.corp.test matches every depth below corp.test but not the apex"
	start_client nw 10.99.0.43 "$(rules '["**.corp.test"]')" --dns "$DUMMY_DNS"
	for n in x.corp.test x.y.corp.test x.y.z.corp.test; do
		cexec nw "nslookup $n"
		assert_contains "10.99.0.10" "$n resolves"
	done
	curl_in nw "http://x.y.z.corp.test:8080/"
	assert_contains "hello from web-a" "x.y.z.corp.test is reachable"
	cexec nw "nslookup corp.test"
	assert_contains "NXDOMAIN" "the apex corp.test is denied"
	cexec nw "nslookup x.other.test"
	assert_contains "NXDOMAIN" "a name under another zone is denied"
	rm_containers nw
	sc_end
}

s07() {
	sc_begin 07 apex-and-nested "Listing the apex and **. allows the whole zone"
	start_client an 10.99.0.44 "$(rules '["corp.test", "**.corp.test"]')" --dns "$DUMMY_DNS"
	for n in corp.test x.corp.test x.y.corp.test; do
		cexec an "nslookup $n"
		assert_contains "10.99.0.10" "$n resolves"
	done
	curl_in an "http://corp.test:8080/"
	assert_contains "hello from web-a" "the apex is reachable"
	rm_containers an
	sc_end
}

s08() {
	sc_begin 08 cname "Addresses behind a CNAME are allowed, the CNAME target is not"
	start_client cn 10.99.0.45 "$(rules '["alias.corp.test"]')" --dns "$DUMMY_DNS"
	cexec cn "nslookup alias.corp.test"
	assert_contains "10.99.0.10" "alias.corp.test resolves through its CNAME"
	curl_in cn "http://alias.corp.test:8080/"
	assert_contains "hello from web-a" "alias.corp.test is reachable"
	set_elements cn 0
	assert_contains "10.99.0.10" "the final address is in the set"
	cexec cn "nslookup a.corp.test"
	assert_contains "NXDOMAIN" "the CNAME target is not allowed to be queried itself"
	rm_containers cn
	sc_end
}

s09() {
	sc_begin 09 ports "Only the configured port and protocol are opened"
	start_client pt 10.99.0.46 "$(rules '["a.corp.test"]' 8080)" --dns "$DUMMY_DNS"
	curl_in pt "http://a.corp.test:8080/"
	assert_contains "hello from web-a" "tcp/8080 is allowed"
	curl_in pt "http://a.corp.test:2222/"
	assert_fail "tcp/2222 is denied although web-a listens on it"
	hostsh "nft list chain ip filter whalewall-pt-$(cid pt)"
	rm_containers pt
	sc_end
}

s10() {
	sc_begin 10 ttl-expiry "Allowed addresses expire with their TTL, open connections survive"
	start_client tt 10.99.0.47 "$(rules '["ttl.corp.test"]')" --dns "$DUMMY_DNS"
	say "the zone TTL is 2s, whalewall runs with -dns-min-ttl 1s -dns-grace 1s"
	cexec tt "(curl -sS -m 12 http://ttl.corp.test:8080/slow >/tmp/slow.out 2>&1 &) ; sleep 0.5; cat /tmp/slow.out"
	set_elements tt 0
	assert_contains "10.99.0.10" "the address is allowed after resolving"
	say "waiting for the entry to expire"
	sleep 5
	set_elements tt 0
	assert_not_contains "10.99.0.10" "the entry expired"
	curl_in tt "$WEBA"
	assert_fail "a new connection to the address is denied"
	sleep 5
	cexec tt "cat /tmp/slow.out"
	assert_contains "tick 8" "the connection opened before expiry kept streaming"
	say "resolving again re-opens the address"
	curl_in tt "http://ttl.corp.test:8080/"
	assert_contains "hello from web-a" "reachable again after a new lookup"
	rm_containers tt
	sc_end
}

s11() {
	sc_begin 11 dns-bypass "Querying other resolvers or using other DNS transports does not bypass the policy"
	start_client bp 10.99.0.48 "$(rules '["a.corp.test"]')" --dns "$DUMMY_DNS"
	say "a query to a public resolver is redirected to whalewall"
	cexec bp "nslookup b.corp.test 8.8.8.8"
	assert_contains "NXDOMAIN" "b.corp.test is denied even when asking 8.8.8.8"
	cexec bp "nslookup a.corp.test 8.8.8.8"
	assert_contains "10.99.0.10" "a.corp.test is answered by whalewall for 8.8.8.8"
	say "DNS over TCP is redirected too"
	say "raw DNS-over-TCP query for b.corp.test sent to 9.9.9.9; flags 81 83 mean NXDOMAIN"
	cexec bp "printf '\\x00\\x1d\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x01b\\x04corp\\x04test\\x00\\x00\\x01\\x00\\x01' | nc -w 2 9.9.9.9 53 | od -An -tx1"
	assert_contains "81 83" "b.corp.test is denied over TCP (rcode NXDOMAIN)"
	say "a query to an address that is not a DNS server is redirected as well"
	cexec bp "nslookup b.corp.test 10.99.0.20"
	assert_contains "NXDOMAIN" "b.corp.test is denied when asking web-b"
	say "Docker's embedded resolver forwards to whalewall"
	cexec bp "nslookup b.corp.test 127.0.0.11"
	assert_contains "NXDOMAIN" "b.corp.test is denied through 127.0.0.11"
	say "DNS over TLS"
	cexec bp "nc -w 2 -z 1.1.1.1 853"
	assert_fail "tcp/853 to a public resolver is dropped"
	cexec bp "nc -w 2 -z 10.99.0.20 853"
	assert_fail "tcp/853 to another host is dropped"
	assert_eq "$(fakedns_queries b.corp.test)" 0 "no denied name reached the upstream"
	ww_log_excerpt 'denied DNS query.*bp' 2
	assert_contains "bp" "denied queries are logged with the container name"
	rm_containers bp
	sc_end
}

s12() {
	sc_begin 12 aaaa "AAAA queries follow the container's IPv6 capability"
	start_client v4 10.99.0.49 "$(rules '["a.corp.test"]')" --dns "$DUMMY_DNS"
	if has_v6; then
		cexec v4 "nslookup -type=AAAA a.corp.test"
		assert_contains "fd00:99::10" "a dual-stack container gets the AAAA record"
		curl_in v4 "-g -6 http://a.corp.test:8080/"
		assert_contains "hello from web-a" "reachable over IPv6"
	else
		cexec v4 "nslookup -type=AAAA a.corp.test"
		assert_not_contains "Name:" "an IPv4-only container gets an empty AAAA answer"
		hostsh "grep -c ' a.corp.test. AAAA' $OUT/queries.log || true"
		assert_eq "$LAST_OUT" 0 "the AAAA query was not forwarded upstream"
	fi
	rm_containers v4
	sc_end
}

s13() {
	sc_begin 13 ipv6-rules "IPv6 works with ips rules, neighbor discovery and the default drop"
	if ! has_v6; then
		sc_skip "needs a Docker daemon with IPv6 (E2E_IPV6=1)"
		return
	fi
	start_client v6 10.99.0.50 'output:
  - ips: ["fd00:99::10"]
    proto: tcp
    dst_ports: [8080]
  - ips: ["10.99.0.10"]
    proto: tcp
    dst_ports: [8080]'
	curl_in v6 "-g -6 http://[fd00:99::10]:8080/"
	assert_contains "hello from web-a" "web-a is reachable over IPv6 (neighbor discovery works)"
	curl_in v6 "-g -6 http://[fd00:99::20]:8080/"
	assert_fail "web-b is unreachable over IPv6"
	curl_in v6 "$WEBA"
	assert_contains "hello from web-a" "web-a is still reachable over IPv4"
	curl_in v6 "$WEBB"
	assert_fail "web-b is unreachable over IPv4"
	cexec v6 "ping -6 -c1 -W2 fd00:99::1"
	assert_fail "ICMPv6 echo to the gateway is dropped"
	hostsh "nft list chain ip6 filter whalewall-v6-$(cid v6)"
	rm_containers v6
	sc_end
}

s14() {
	sc_begin 14 per-container "Each container has its own policy"
	start_client ca 10.99.0.51 "$(rules '["a.corp.test"]')" --dns "$DUMMY_DNS"
	start_client cb 10.99.0.52 "$(rules '["b.corp.test"]')" --dns "$DUMMY_DNS"
	curl_in ca "http://a.corp.test:8080/"
	assert_contains "hello from web-a" "ca reaches web-a by name"
	cexec ca "nslookup b.corp.test"
	assert_contains "NXDOMAIN" "ca can not resolve b.corp.test"
	curl_in ca "$WEBB"
	assert_fail "ca can not reach web-b by IP"
	curl_in cb "http://b.corp.test:8080/"
	assert_contains "hello from web-b" "cb reaches web-b by name"
	cexec cb "nslookup a.corp.test"
	assert_contains "NXDOMAIN" "cb can not resolve a.corp.test"
	curl_in cb "$WEBA"
	assert_fail "cb can not reach web-a by IP"
	rm_containers ca cb
	sc_end
}

s15() {
	sc_begin 15 unmanaged "Containers without the whalewall label are not touched"
	start_plain um 10.99.0.53 --dns "$DUMMY_DNS"
	curl_in um "$WEBA"
	assert_contains "hello from web-a" "an unmanaged container reaches web-a"
	curl_in um "$WEBB"
	assert_contains "hello from web-b" "an unmanaged container reaches web-b"
	hostsh "nft list table ip whalewall-nat 2>/dev/null | grep -c 10.99.0.53 || true"
	assert_eq "$LAST_OUT" 0 "its DNS traffic is not redirected"
	cexec um "nslookup a.corp.test"
	assert_not_contains "10.99.0.10" "its queries do not reach whalewall's resolver"
	rm_containers um
	sc_end
}

s16() {
	sc_begin 16 lifecycle "Stopping a container removes its rules, sets and DNS state"
	start_client lc1 10.99.0.54 "$(rules '["a.corp.test"]')" --dns "$DUMMY_DNS"
	curl_in lc1 "http://a.corp.test:8080/"
	assert_contains "hello from web-a" "the container reaches a.corp.test"
	local id
	id=$(cid lc1)
	hostsh "nft list ruleset 2>/dev/null | grep -c 'ww-$id' || true"
	assert_eq "$((LAST_OUT > 0))" 1 "its set and rules exist"
	hostsh "nft list table ip whalewall-nat 2>/dev/null | grep -c 10.99.0.54 || true"
	assert_eq "$LAST_OUT" 2 "its two DNS redirect rules exist"
	say "the container is removed"
	run docker rm -f lc1
	sleep 2
	hostsh "nft list ruleset 2>/dev/null | grep -c 'ww-$id\|whalewall-lc1' || true"
	assert_eq "$LAST_OUT" 0 "its sets and chains are gone"
	hostsh "nft list table ip whalewall-nat 2>/dev/null | grep -c 10.99.0.54 || true"
	assert_eq "$LAST_OUT" 0 "its DNS redirect rules are gone"
	say "a new container reuses the IP address"
	start_client lc2 10.99.0.54 -
	curl_in lc2 "$WEBA"
	assert_fail "the new container inherits no allowance for web-a"
	cexec lc2 "nslookup a.corp.test 10.99.0.1"
	assert_fail "and can not use the resolver"
	rm_containers lc2
	sc_end
}

s17() {
	sc_begin 17 restart "Restarting whalewall keeps allowances and does not duplicate rules"
	start_client rs 10.99.0.55 "$(rules '["a.corp.test"]')" --dns "$DUMMY_DNS"
	curl_in rs "http://a.corp.test:8080/"
	assert_contains "hello from web-a" "reachable before the restart"
	local chain before after
	chain=whalewall-rs-$(cid rs)
	before=$(nft list chain ip filter "$chain" | wc -l)
	hostsh "nft list set ip filter ww-$(cid rs)-0-4"
	say "whalewall is stopped; the kernel rules and the allowed address stay in place"
	ww_stop
	curl_in rs "$WEBA"
	assert_contains "hello from web-a" "the allowed address is still reachable while whalewall is stopped"
	cexec rs "nslookup b.corp.test"
	assert_fail "new lookups fail while the resolver is down"
	say "whalewall is started again"
	ww_start
	sleep 2
	after=$(nft list chain ip filter "$chain" | wc -l)
	assert_eq "$after" "$before" "the container chain has the same number of lines ($before)"
	hostsh "nft list table ip whalewall-nat 2>/dev/null | grep -c 10.99.0.55 || true"
	assert_eq "$LAST_OUT" 2 "there are still exactly two redirect rules"
	cexec rs "nslookup b.corp.test"
	assert_contains "NXDOMAIN" "the resolver enforces the policy again after the restart"
	curl_in rs "http://a.corp.test:8080/"
	assert_contains "hello from web-a" "reachable after the restart"
	rm_containers rs
	sc_end
}

s18() {
	sc_begin 18 ipv6-not-managed "A container with IPv6 is refused loudly when IPv6 can not be managed"
	if ! has_v6; then
		sc_skip "needs a Docker daemon with IPv6 (E2E_IPV6=1)"
		return
	fi
	say "Docker's DOCKER-USER chain for IPv6 is hidden to simulate ip6tables being disabled"
	ww_stop
	hostsh "nft rename chain ip6 filter DOCKER-USER DOCKER-USER-hidden"
	ww_start
	start_client fc 10.99.0.56 "$(rules '["a.corp.test"]')" --dns "$DUMMY_DNS"
	ww_log_excerpt 'container.name\":\"fc\".*IPv6' 1
	assert_contains "IPv6 traffic can't be managed" "whalewall refuses to manage the container and says why"
	ww_stop
	hostsh "nft rename chain ip6 filter DOCKER-USER-hidden DOCKER-USER"
	rm_containers fc
	ww_start
	sc_end
}

s19() {
	sc_begin 19 sandbox "whalewall runs with landlock and seccomp while serving DNS"
	ww_log_excerpt 'applied (landlock|seccomp)' 2
	assert_contains "seccomp" "seccomp filters are applied"
	hostsh "kill -0 $WW_PID && echo whalewall is running"
	assert_contains "whalewall is running" "the process survived serving queries from every scenario"
	say "kernel audit records of seccomp kills (type=1326) for the whalewall binary since this run started: $(seccomp_events)"
	assert_eq "$(seccomp_events)" 0 "no seccomp violation was recorded for whalewall"
	sc_end
}

s20() {
	sc_begin 20 regression "Rules without domains behave exactly as before"
	start_client rg 10.99.0.57 'output:
  - ips: ["10.99.0.10"]
    proto: tcp
    dst_ports: [8080]'
	curl_in rg "$WEBA"
	assert_contains "hello from web-a" "an ips rule allows web-a"
	curl_in rg "$WEBB"
	assert_fail "web-b stays unreachable"
	curl_in rg "http://10.99.0.10:2222/"
	assert_fail "other ports stay unreachable"
	hostsh "nft list table ip whalewall-nat 2>/dev/null | grep -c 10.99.0.57 || true"
	assert_eq "$LAST_OUT" 0 "the container's DNS traffic is not redirected"
	hostsh "nft list ruleset 2>/dev/null | grep -c 'ww-$(cid rg)' || true"
	assert_eq "$LAST_OUT" 0 "no domain sets were created"
	rm_containers rg
	sc_end
}

s21() {
	sc_begin 21 shared-ip "Known limitation: an allowed address is open for every name behind it"
	start_client sh 10.99.0.58 "$(rules '["shared.corp.test"]')" --dns "$DUMMY_DNS"
	curl_in sh "http://shared.corp.test:8080/"
	assert_contains "hello from web-a" "shared.corp.test is reachable"
	say "a.corp.test is denied by DNS, but shares the allowed address"
	cexec sh "nslookup a.corp.test"
	assert_contains "NXDOMAIN" "a.corp.test can not be resolved"
	curl_in sh "$WEBA"
	assert_contains "hello from web-a" "a direct connection to the shared address works (known limitation)"
	rm_containers sh
	sc_end
}

s22() {
	sc_begin 22 unit-tests "Unit tests"
	run sh -c "cd '$ROOT' && go test -count=1 -race ./dnsproxy/ 2>&1 | tail -n 3"
	assert_rc 0 "resolver tests pass"
	run sh -c "cd '$ROOT' && go test -count=1 -run 'TestParseDomainPattern|TestDomain|TestConfig|TestRuleCreation|TestDeletingContainers|TestCreationIdempotency|TestCancelingCreation|TestIPv6' -v . 2>&1 | grep -E '^(--- (FAIL|PASS)|ok|FAIL|PASS)' | sort | uniq -c | sort -rn | head -n 12"
	assert_contains "ok" "domain, config and rule creation tests pass"
	sc_end
}

s23() {
	sc_begin 23 clear "whalewall -clear removes everything it created"
	rm_containers $(docker ps -aq --filter label=whalewall.enabled=true) 2>/dev/null
	sleep 2
	ww_stop
	run "$WW" -clear -d "$OUT/data" -l "$OUT/clear.log"
	hostsh "nft list tables | grep -c whalewall || true"
	assert_eq "$LAST_OUT" 0 "no whalewall tables remain"
	hostsh "nft list ruleset 2>/dev/null | grep -c 'whalewall\|ww-' || true"
	local left=$LAST_OUT
	if [ "$left" != 0 ]; then
		say "leftovers:"
		hostsh "nft -a list ruleset 2>/dev/null | grep -B2 'whalewall\|ww-'"
	fi
	assert_eq "$left" 0 "no whalewall chains, sets or rules remain"
	sc_end
	ww_start
}

# ----------------------------------------------------------------- main

setup
for n in 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21 22 23; do
	want "$n" && "s$n"
done

echo
echo "passed: $PASS_COUNT  failed: $FAIL_COUNT  skipped: $SKIP_COUNT"
[ "$FAIL_COUNT" = 0 ]
