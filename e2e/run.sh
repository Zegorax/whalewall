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
	CGO_ENABLED=0 go build -o "$ROOT/e2e/bin/attack" ./e2e/tools/attack || exit 1
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
kube.corp.test A 60 10.99.0.10
c.corp.test A 60 10.98.0.10
forever.corp.test A 4294967295 10.99.0.10
rebind.corp.test A 60 10.99.0.1
rebind.corp.test A 60 127.0.0.1
rebind.corp.test A 60 169.254.169.254
gw.corp.test A 60 10.99.0.1
gw2.corp.test A 60 10.98.0.1
EOF
	# every address the host itself has, any of them reaches host services
	local n=0 hostip
	for hostip in $(awk '/\|--/ {a=$2} /\/32 host LOCAL/ {print a}' /proc/net/fib_trie | sort -u | grep -v '^127\.'); do
		n=$((n + 1))
		echo "host$n.corp.test A 60 $hostip" >>"$OUT/zone.txt"
	done
	HOST_NAMES=$n
	# an answer with far more addresses than should ever be allowed
	for i in $(seq 1 300); do
		echo "many.corp.test A 60 10.99.$((1 + i / 250)).$((i % 250 + 1))" >>"$OUT/zone.txt"
	done
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

	# a second network and a host service for the adversarial scenarios
	docker network rm "$NET2" >/dev/null 2>&1
	docker network create --subnet 10.98.0.0/24 "$NET2" >/dev/null || exit 1
	docker rm -f web-c >/dev/null 2>&1
	docker run -d --name web-c --network "$NET2" --ip 10.98.0.10 -v "$ROOT/e2e/bin:/e2e:ro" --entrypoint /e2e/web "$IMG" -name web-c >/dev/null || exit 1
	"$ROOT/e2e/bin/web" -name host-web -ports 8080,9999 >"$OUT/hostweb.out" 2>&1 &
	HOSTWEB_PID=$!

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
	[ -n "${HOSTWEB_PID:-}" ] && kill "$HOSTWEB_PID" 2>/dev/null
	docker ps -aq --filter "network=$NET2" | xargs -r docker rm -f >/dev/null 2>&1
	docker network rm "$NET" "$NET2" >/dev/null 2>&1
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

# --------------------------------------------------- adversarial scenarios

# rawdns <container> <printf string> sends a hand-made DNS message to a
# public address (which whalewall redirects to its resolver) and logs the
# start of the answer and its response code.
rawdns() {
	local c=$1 pkt=$2
	cexec "$c" "printf '$pkt' | nc -u -w 2 8.8.8.8 53 | od -An -tx1 | head -n 1 | awk '{print; print \"rcode=\" substr(\$4, 2, 1)}'"
}

DNS_HDR='\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
DNS_KUBE='\x04kube\x04corp\x04test\x00'

s24() {
	sc_begin 24 dns-protocol-abuse "Hand-made DNS messages can not be used to get around the policy"
	start_client pa 10.99.0.71 "$(rules '["kube.corp.test"]')" --dns "$DUMMY_DNS"
	local before
	before=$(fakedns_queries kube.corp.test)

	say "a valid query for the allowed name works"
	rawdns pa "$DNS_HDR$DNS_KUBE\x00\x01\x00\x01"
	assert_contains "rcode=0" "the allowed name is answered"
	assert_eq "$(fakedns_queries kube.corp.test)" "$((before + 1))" "it was forwarded to the upstream once"

	say "the Kelvin sign (U+212A) folds to k with Unicode lower-casing; it must not be treated as kube.corp.test"
	rawdns pa "$DNS_HDR\x06\xe2\x84\xaaube\x04corp\x04test\x00\x00\x01\x00\x01"
	assert_contains "rcode=3" "the look-alike name is denied"
	say "a dot inside a label, and a NUL inside a label"
	rawdns pa "$DNS_HDR\x09kube.corp\x04test\x00\x00\x01\x00\x01"
	assert_contains "rcode=3" "a dot inside a label is denied"
	rawdns pa "$DNS_HDR\x05kube\x00\x04corp\x04test\x00\x00\x01\x00\x01"
	assert_contains "rcode=3" "a NUL inside a label is denied"

	say "other classes and record types that would reveal more than a lookup"
	rawdns pa "$DNS_HDR$DNS_KUBE\x00\x10\x00\x03"
	assert_contains "rcode=5" "a CHAOS class query is refused"
	rawdns pa "$DNS_HDR$DNS_KUBE\x00\xfc\x00\x01"
	assert_contains "rcode=5" "a zone transfer (AXFR) is refused"
	rawdns pa "$DNS_HDR$DNS_KUBE\x00\xff\x00\x01"
	assert_contains "rcode=5" "an ANY query is refused"

	say "two questions in one message, the second for a denied name"
	rawdns pa "\x12\x34\x01\x00\x00\x02\x00\x00\x00\x00\x00\x00$DNS_KUBE\x00\x01\x00\x01\x04evil\x05other\x04test\x00\x00\x01\x00\x01"
	assert_contains "rcode=1" "the message is rejected as malformed"
	say "an UPDATE message"
	rawdns pa "\x12\x34\x28\x00\x00\x01\x00\x00\x00\x00\x00\x00$DNS_KUBE\x00\x06\x00\x01"
	assert_contains "rcode=4" "the opcode is not implemented"

	say "random bytes and a truncated header get no answer"
	cexec pa "head -c 64 /dev/urandom | nc -u -w 1 8.8.8.8 53 | od -An -tx1 | head -n 1"
	cexec pa "printf '\x12\x34\x01' | nc -u -w 1 8.8.8.8 53 | od -An -tx1 | head -n 1"
	say "the resolver is still alive and enforcing the policy"
	rawdns pa "$DNS_HDR$DNS_KUBE\x00\x01\x00\x01"
	assert_contains "rcode=0" "the allowed name still works"
	cexec pa "nslookup evil.other.test"
	assert_contains "NXDOMAIN" "a denied name is still denied"
	hostsh "kill -0 $WW_PID && echo whalewall is running"
	assert_contains "whalewall is running" "whalewall did not crash"
	assert_eq "$(fakedns_queries kube.corp.test)" "$((before + 2))" "only the two valid queries reached the upstream"
	assert_eq "$(fakedns_queries evil.other.test)" 0 "the denied name never reached the upstream"
	rm_containers pa
	sc_end
}

s25() {
	sc_begin 25 host-protection "A permitted name can not be made to point at the host"
	start_client hp 10.99.0.72 "$(rules '["**.corp.test"]')" --dns "$DUMMY_DNS"
	say "a service on the host listens on 8080 and 9999"
	hostsh "curl -sS -m 3 http://127.0.0.1:8080/"
	assert_contains "hello from host-web" "the host service works"

	say "names that resolve to the host, loopback and the cloud metadata address"
	for n in gw rebind; do
		cexec hp "nslookup $n.corp.test"
		assert_not_contains "Address: 10.99.0.1" "$n.corp.test does not return the gateway"
		assert_not_contains "Address: 127." "$n.corp.test does not return loopback"
		assert_not_contains "Address: 169.254" "$n.corp.test does not return the link-local address"
	done
	say "the gateway of another network, and every address of the host, are the host too"
	cexec hp "nslookup gw2.corp.test"
	assert_not_contains "Address: 10.98.0.1" "gw2.corp.test does not return the gateway of the other network"
	local k
	for k in $(seq 1 "${HOST_NAMES:-0}"); do
		cexec hp "nslookup host$k.corp.test"
		assert_not_contains "Address: 1" "host$k.corp.test does not return an address of the host"
	done
	curl_in hp "http://gw.corp.test:8080/"
	assert_fail "the name that points at the host is not usable"
	set_elements hp 0
	assert_not_contains "10.99.0.1 " "the gateway is not in the container's set"

	say "reaching the host directly"
	curl_in hp "http://$GW4:8080/"
	assert_fail "the host's service on the gateway is unreachable"
	curl_in hp "http://$GW4:9999/"
	assert_fail "the host's other port is unreachable"
	cexec hp "nc -w 2 -z $GW4 22"
	assert_fail "ssh on the gateway is unreachable"
	rm_containers hp
	sc_end
}

s26() {
	sc_begin 26 answer-abuse "Huge TTLs and huge answers do not open the firewall for long or wide"
	start_client aa 10.99.0.73 "$(rules '["**.corp.test"]')" --dns "$DUMMY_DNS"
	say "whalewall runs with -dns-max-ttl 20s; forever.corp.test has a TTL of 4294967295 seconds"
	cexec aa "nslookup forever.corp.test"
	assert_contains "10.99.0.10" "the name resolves"
	set_elements aa 0
	assert_contains "timeout 21s" "the entry lives at most max TTL plus grace, not 136 years"
	say "many.corp.test has 300 addresses; the container is shown how many?"
	cexec aa "nslookup many.corp.test | grep -c Address"
	local shown=$LAST_OUT
	hostsh "nft list set ip filter ww-$(cid aa)-0-4 | grep -o '10\.99\.[0-9]*\.[0-9]*' | sort -u | grep -v '10\.99\.0\.10$' | wc -l"
	local inset=$LAST_OUT
	if [ "$inset" -le 64 ] && [ "$inset" -gt 0 ]; then pass "at most 64 of the 300 addresses were allowed ($inset)"; else fail "$inset addresses were allowed"; fi
	if [ "$shown" -le 70 ]; then pass "the container saw at most 64 of them too ($shown address lines)"; else fail "the container was shown $shown address lines"; fi
	say "an address beyond the cap is not reachable"
	curl_in aa "http://10.99.2.50:8080/"
	assert_fail "an address that was cut off is not allowed"
	rm_containers aa
	sc_end
}

s27() {
	sc_begin 27 other-protocols "ICMP and other tricks do not get through to allowed addresses"
	start_plain pg 10.99.0.74
	cexec pg "ping -c 1 -W 2 10.99.0.10"
	assert_rc 0 "an unmanaged container can ping web-a (the tool works)"
	start_client rp 10.99.0.75 "$(rules '["a.corp.test"]')" --dns "$DUMMY_DNS"
	curl_in rp "http://a.corp.test:8080/"
	assert_contains "hello from web-a" "the allowed name works over tcp/8080"
	cexec rp "ping -c 1 -W 2 10.99.0.10"
	assert_fail "ICMP echo to the allowed address is dropped"
	cexec rp "ping -c 1 -W 2 $GW4"
	assert_fail "ICMP echo to the gateway is dropped"
	cexec rp "ping -c 1 -W 2 10.99.0.20"
	assert_fail "ICMP echo to another container is dropped"
	cexec rp "nc -w 2 -z -p 53 10.99.0.20 8080"
	assert_fail "using source port 53 does not open web-b"
	cexec rp "nc -w 2 -z -p 8080 10.99.0.20 8080"
	assert_fail "using source port 8080 does not open web-b"
	rm_containers pg rp
	sc_end
}

s28() {
	sc_begin 28 multi-network "A container on two networks is filtered on both"
	docker rm -f mn >/dev/null 2>&1
	run docker create --name mn --network "$NET" --ip 10.99.0.62 --dns "$DUMMY_DNS" --entrypoint sleep -l whalewall.enabled=true -l "whalewall.rules=$(rules '["**.corp.test"]')" "$IMG" infinity
	run docker network connect --ip 10.98.0.62 "$NET2" mn
	run docker start mn
	wait_rules mn
	cexec mn "nslookup a.corp.test"
	assert_contains "10.99.0.10" "a.corp.test resolves"
	curl_in mn "http://a.corp.test:8080/"
	assert_contains "hello from web-a" "web-a is reachable on the first network"
	curl_in mn "http://c.corp.test:8080/"
	assert_contains "hello from web-c" "web-c is reachable on the second network by name"
	curl_in mn "http://10.99.0.20:8080/"
	assert_fail "web-b is unreachable by IP on the first network"
	curl_in mn "http://10.98.0.10:2222/"
	assert_fail "web-c's other port is unreachable"
	hostsh "nft list table ip whalewall-nat | grep -c 'saddr 10.9[89].0.62' || true"
	assert_eq "$LAST_OUT" 4 "DNS is redirected for both addresses (udp and tcp each)"
	set_elements mn 0
	assert_contains "10.98.0.10" "the address behind the second network is in the set"
	rm_containers mn
	sc_end
}

s29() {
	sc_begin 29 churn "Starting and removing many containers at once leaves nothing behind"
	local i pids=()
	for i in $(seq 1 12); do
		(docker run -d --name "ch$i" --network "$NET" --ip "10.99.0.$((110 + i))" --dns "$DUMMY_DNS" --entrypoint sleep \
			-l whalewall.enabled=true -l "whalewall.rules=$(rules '["a.corp.test"]')" "$IMG" infinity >/dev/null 2>&1) &
		pids+=($!)
	done
	wait "${pids[@]}"
	for i in $(seq 1 12); do wait_rules "ch$i"; done
	hostsh "nft list table ip filter 2>/dev/null | grep -c 'set ww-' || true"
	assert_eq "$LAST_OUT" 12 "every container has its own IPv4 set"
	for i in 1 6 12; do
		curl_in "ch$i" "http://a.corp.test:8080/"
		assert_contains "hello from web-a" "ch$i reaches a.corp.test"
		curl_in "ch$i" "http://10.99.0.20:8080/"
		assert_fail "ch$i can not reach web-b"
	done
	say "queries from all containers at once"
	pids=()
	for i in $(seq 1 12); do
		(docker exec "ch$i" sh -c 'for n in 1 2 3 4 5; do nslookup a.corp.test >/dev/null 2>&1; nslookup evil.other.test >/dev/null 2>&1; done' >/dev/null 2>&1) &
		pids+=($!)
	done
	wait "${pids[@]}"
	hostsh "kill -0 $WW_PID && echo whalewall is running"
	assert_contains "whalewall is running" "whalewall survived the load"

	say "all containers are removed at the same time"
	pids=()
	for i in $(seq 1 12); do
		(docker rm -f "ch$i" >/dev/null 2>&1) &
		pids+=($!)
	done
	wait "${pids[@]}"
	sleep 5
	hostsh "nft list ruleset 2>/dev/null | grep -c 'ww-\|whalewall-ch' || true"
	assert_eq "$LAST_OUT" 0 "no sets, chains or rules are left"
	hostsh "nft list table ip whalewall-nat 2>/dev/null | grep -c 'saddr 10.99.0.1[0-9][0-9]' || true"
	assert_eq "$LAST_OUT" 0 "no DNS redirect rules are left"

	say "the same name and address are reused five times in a row"
	for i in 1 2 3 4 5; do
		docker run -d --name flap --network "$NET" --ip 10.99.0.140 --dns "$DUMMY_DNS" --entrypoint sleep \
			-l whalewall.enabled=true -l "whalewall.rules=$(rules '["a.corp.test"]')" "$IMG" infinity >/dev/null
		wait_rules flap
		docker rm -f flap >/dev/null
		sleep 0.5
	done
	sleep 3
	hostsh "nft list ruleset 2>/dev/null | grep -c 'ww-\|whalewall-flap' || true"
	assert_eq "$LAST_OUT" 0 "nothing is left after the flapping container"
	say "kernel audit records of seccomp kills for whalewall since this run started: $(seccomp_events)"
	assert_eq "$(seccomp_events)" 0 "whalewall was not killed by seccomp"
	sc_end
}

s30() {
	sc_begin 30 network-connect "Known limitation: a network connected after start is not managed"
	start_client nc2 10.99.0.64 "$(rules '["a.corp.test"]')" --dns "$DUMMY_DNS"
	curl_in nc2 "http://10.98.0.10:8080/"
	assert_fail "web-c on the second network is unreachable before connecting"
	say "an administrator connects the running container to a second network"
	run docker network connect --ip 10.98.0.64 "$NET2" nc2
	sleep 2
	curl_in nc2 "http://10.98.0.10:8080/"
	assert_contains "hello from web-c" "the new interface is not filtered (whalewall only sees container starts)"
	say "this needs access to the Docker API, a container can not do it itself; restart the container to apply rules to all its networks"
	rm_containers nc2
	sc_end
}

s31() {
	sc_begin 31 source-spoofing "Forged source addresses: a known limitation with NET_RAW, closed by dropping it"
	local mount=(-v "$ROOT/e2e/bin:/e2e:ro")
	start_client sp-vip 10.99.0.81 'output:
  - ips: ["10.99.0.20"]
    proto: udp
    dst_ports: [9999]' "${mount[@]}"
	start_client sp-atk 10.99.0.80 "$(rules '["a.corp.test"]')" --dns "$DUMMY_DNS" "${mount[@]}"
	start_client sp-safe 10.99.0.82 "$(rules '["a.corp.test"]')" --dns "$DUMMY_DNS" --cap-drop NET_RAW "${mount[@]}"

	udp_listen() {
		docker exec web-b sh -c 'killall nc 2>/dev/null; rm -f /tmp/udp.out' >/dev/null 2>&1
		docker exec -d web-b sh -c 'nc -u -l -p 9999 > /tmp/udp.out'
		sleep 0.5
	}
	udp_got() { sleep 1; cexec web-b "cat /tmp/udp.out 2>/dev/null"; }

	say "baseline: the container that is allowed to send UDP to web-b can"
	udp_listen
	cexec sp-vip "echo from-vip | nc -u -w 1 10.99.0.20 9999"
	udp_got
	assert_contains "from-vip" "an allowed UDP packet arrives"

	say "the attacker is not allowed to"
	udp_listen
	cexec sp-atk "echo from-atk | nc -u -w 1 10.99.0.20 9999"
	udp_got
	assert_not_contains "from-atk" "a plain UDP packet of the attacker is dropped"

	say "binding to another container's address is not possible without extra capabilities"
	udp_listen
	cexec sp-atk "echo bound | nc -u -w 1 -s 10.99.0.81 10.99.0.20 9999"
	assert_fail "nc can not bind to an address the container does not have"
	cexec sp-atk "ip addr add 10.99.0.81/24 dev eth0"
	assert_fail "the container can not add the address to its interface"

	say "KNOWN LIMITATION: with NET_RAW (a default Docker capability) a raw socket can forge the source address of another container"
	udp_listen
	cexec sp-atk "/e2e/attack spoof -src 10.99.0.81 -dst 10.99.0.20 -port 9999 -msg spoofed-as-vip"
	udp_got
	assert_contains "spoofed-as-vip" "the forged packet is accepted as if it came from the allowed container"
	say "whalewall tells the administrator about this: see the log line below"
	ww_log_excerpt 'can forge source addresses.*sp-atk' 1
	assert_contains "NET_RAW" "whalewall warns that the container keeps NET_RAW"

	say "the fix is to drop NET_RAW, in compose: cap_drop: [NET_RAW]"
	udp_listen
	cexec sp-safe "/e2e/attack spoof -src 10.99.0.81 -dst 10.99.0.20 -port 9999 -msg spoofed-as-vip2"
	assert_contains "raw socket not allowed" "a container without NET_RAW can not open a raw socket"
	udp_got
	assert_not_contains "spoofed-as-vip2" "nothing arrives"
	rm_containers sp-vip sp-atk sp-safe
	sc_end
}

s32() {
	sc_begin 32 stale-allowance "An address allowed through a container rule is not usable after that container is gone"
	local mount=(-v "$ROOT/e2e/bin:/e2e:ro")
	docker rm -f st-srv st-other >/dev/null 2>&1

	say "a container rule needs the target to be managed; if it is not, the rules are invalid and the container is isolated"
	run docker run -d --name st-srv --network "$NET" --ip 10.99.0.150 "${mount[@]}" --entrypoint /e2e/web "$IMG" -name st-srv
	start_client st-bad 10.99.0.153 "output:
  - network: $NET
    container: st-srv
    proto: tcp
    dst_ports: [8080]"
	ww_log_excerpt 'does not have whalewall enabled' 1
	assert_contains "does not have whalewall enabled" "whalewall rejects a container rule for an unmanaged target"
	curl_in st-bad "http://10.99.0.150:8080/"
	assert_fail "the container with the invalid rule can not reach the target"
	curl_in st-bad "$WEBA"
	assert_fail "and is isolated from everything else, not left unmanaged"
	rm_containers st-srv st-bad

	say "the usual case, both managed"
	run docker run -d --name st-srv --network "$NET" --ip 10.99.0.150 -l whalewall.enabled=true "${mount[@]}" --entrypoint /e2e/web "$IMG" -name st-srv
	wait_rules st-srv
	start_client st-cli 10.99.0.151 "output:
  - network: $NET
    container: st-srv
    proto: tcp
    dst_ports: [8080]"
	curl_in st-cli "http://10.99.0.150:8080/"
	assert_contains "hello from st-srv" "the container rule lets st-cli reach st-srv"
	curl_in st-cli "$WEBA"
	assert_fail "st-cli can not reach anything else"
	say "st-srv is removed and its address goes to an unrelated container"
	rm_containers st-srv
	sleep 2
	run docker run -d --name st-other --network "$NET" --ip 10.99.0.150 "${mount[@]}" --entrypoint /e2e/web "$IMG" -name st-other
	sleep 1
	curl_in st-cli "http://10.99.0.150:8080/"
	assert_not_contains "hello from st-other" "the new owner of the address is not reachable through the old rule"
	say "a container with the allowed name comes back, the rule applies to it again"
	rm_containers st-other
	sleep 1
	run docker run -d --name st-srv --network "$NET" --ip 10.99.0.152 -l whalewall.enabled=true "${mount[@]}" --entrypoint /e2e/web "$IMG" -name st-srv
	wait_rules st-srv
	sleep 2
	curl_in st-cli "http://10.99.0.152:8080/"
	assert_contains "hello from st-srv" "the rule follows the container by name"
	curl_in st-cli "http://10.99.0.150:8080/"
	assert_fail "the old address stays closed"
	rm_containers st-srv st-cli
	sc_end
}

s33() {
	sc_begin 33 published-ports "Published ports are not a way around the rules"
	docker rm -f pub >/dev/null 2>&1
	run docker run -d --name pub --network "$NET" --ip 10.99.0.160 -p 18080:8080 -v "$ROOT/e2e/bin:/e2e:ro" --entrypoint /e2e/web "$IMG" -name pub
	local hostip
	hostip=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n 1)
	say "host address used: ${hostip:-none}"
	start_plain pl2 10.99.0.162
	cexec pl2 "curl -sS -m 4 --connect-timeout 2 http://$GW4:18080/"
	local reachable=$LAST_RC
	start_client hp2 10.99.0.161 "$(rules '["a.corp.test"]')" --dns "$DUMMY_DNS"
	if [ "$reachable" != 0 ]; then
		say "this host does not forward published ports to containers on the gateway address, nothing to attack"
	else
		assert_contains "hello from pub" "an unmanaged container can use the published port (the path exists)"
		curl_in hp2 "http://$GW4:18080/"
		assert_fail "a managed container can not reach pub through the published port on the gateway"
		if [ -n "$hostip" ]; then
			curl_in hp2 "http://$hostip:18080/"
			assert_fail "a managed container can not reach pub through the published port on the host address"
		fi
	fi
	curl_in hp2 "http://10.99.0.160:8080/"
	assert_fail "a managed container can not reach pub directly either"
	rm_containers pub pl2 hp2
	sc_end
}

s34() {
	sc_begin 34 resolver-exposure "The resolver is not an open resolver and does not hold connections for unmanaged hosts"
	local mount=(-v "$ROOT/e2e/bin:/e2e:ro")
	start_plain rx 10.99.0.170 "${mount[@]}"
	say "the resolver listens while a container with domain rules exists on the network"
	start_client rx-anchor 10.99.0.171 "$(rules '["a.corp.test"]')" --dns "$DUMMY_DNS"
	cexec rx "nslookup -port=5353 a.corp.test $GW4"
	assert_not_contains "10.99.0.10" "an unmanaged container gets no answer from the resolver"
	ww_log_excerpt 'refusing query from unmanaged source' 1
	assert_contains "unmanaged source" "whalewall logs the refused query"
	cexec rx "/e2e/attack hold -server $GW4:5353 -n 50 -for 2s"
	assert_contains "alive=0" "the resolver closes every TCP connection of an unmanaged container"
	assert_not_contains "opened=0" "the connections were accepted and then closed, so the check measured something"
	say "queries for names that are not allowed never reach the upstream"
	local before after
	before=$(fakedns_queries evil.other.test)
	cexec rx "nslookup -port=5353 evil.other.test $GW4"
	after=$(fakedns_queries evil.other.test)
	assert_eq "$after" "$before" "the unmanaged query did not reach the upstream"
	rm_containers rx rx-anchor
	sc_end
}

s35() {
	sc_begin 35 dns-flood "A container can not exhaust the resolver or whalewall by flooding it"
	local mount=(-v "$ROOT/e2e/bin:/e2e:ro")
	start_client fl 10.99.0.180 "$(rules '["**.corp.test"]')" --dns "$DUMMY_DNS" "${mount[@]}"
	start_client fl2 10.99.0.181 "$(rules '["**.corp.test"]')" --dns "$DUMMY_DNS"
	local fds_before fds_after q_before q_after
	hostsh "ls /proc/$WW_PID/fd | wc -l"
	fds_before=$LAST_OUT
	q_before=$(fakedns_queries a.corp.test)
	say "3000 queries from 100 senders and 300 idle TCP connections"
	cexec fl "/e2e/attack flood -server $DUMMY_DNS:53 -name a.corp.test. -n 3000 -workers 100 -tcp 300"
	local out=$LAST_OUT answered alive
	answered=$(echo "$out" | sed -n 's/.*answered=\([0-9]*\).*/\1/p')
	alive=$(echo "$out" | sed -n 's/.*tcp_alive=\([0-9]*\).*/\1/p')
	log "answered=$answered alive=$alive"
	local seconds max
	seconds=$(echo "$out" | sed -n 's/.*seconds=\([0-9]*\).*/\1/p')
	# 100 queries per second on average and a burst of 200, with some room
	max=$((250 + 110 * ${seconds:-1}))
	if [ "${answered:-99999}" -le "$max" ] && [ "${answered:-0}" -gt 0 ]; then pass "the flood was limited to $answered answers in ${seconds}s (limit $max)"; else fail "flood answered: $answered in ${seconds}s (limit $max)"; fi
	q_after=$(fakedns_queries a.corp.test)
	if [ $((q_after - q_before)) -le "$max" ]; then pass "the upstream saw $((q_after - q_before)) queries"; else fail "the upstream saw $((q_after - q_before)) queries"; fi
	say "idle TCP connections: a container can keep at most 16 open"
	cexec fl "/e2e/attack hold -server $DUMMY_DNS:53 -n 100 -for 1s"
	alive=$(echo "$LAST_OUT" | sed -n 's/.*alive=\([0-9]*\).*/\1/p')
	if [ "${alive:-999}" -le 16 ] && [ "${alive:-0}" -gt 0 ]; then pass "$alive of 100 idle TCP connections stayed open"; else fail "idle TCP connections kept open: $alive"; fi
	hostsh "ls /proc/$WW_PID/fd | wc -l"
	fds_after=$LAST_OUT
	if [ "$fds_after" -le $((fds_before + 40)) ]; then pass "file descriptors of whalewall: $fds_before before, $fds_after after"; else fail "file descriptors of whalewall: $fds_before before, $fds_after after"; fi
	cexec fl2 "nslookup a.corp.test"
	assert_contains "10.99.0.10" "another container still resolves names"
	hostsh "kill -0 $WW_PID && echo whalewall is running"
	assert_contains "whalewall is running" "whalewall survived the flood"
	ww_log_excerpt 'rate limiting DNS queries' 1
	assert_contains "rate limiting" "the limit was logged"
	say "log lines are sampled, the flood did not write thousands of lines"
	hostsh "grep -c 'rate limiting DNS queries' $OUT/whalewall.log"
	if [ "$LAST_OUT" -lt 100 ]; then pass "$LAST_OUT rate limit log lines"; else fail "$LAST_OUT rate limit log lines"; fi
	rm_containers fl fl2
	sc_end
}

s36() {
	sc_begin 36 hostile-labels "Rule labels made to exhaust whalewall isolate the container and leave whalewall working"
	local bomb big
	bomb='a: &a [x,x,x,x,x,x,x,x,x]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]
h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]
output:
  - ips: *h
    proto: tcp
    dst_ports: [8080]'
	start_client hb1 10.99.0.190 "$bomb" --dns "$DUMMY_DNS"
	ww_log_excerpt 'invalid rules.*hb1' 1
	assert_contains "invalid rules" "an alias bomb is rejected"
	curl_in hb1 "$WEBA"
	assert_fail "the container is isolated"

	# too large for the docker command line (and its --label-file), so the
	# container is created through the API
	docker rm -f hb2 >/dev/null 2>&1
	python3 - "$OUT/big.json" "$IMG" "$NET" <<'PYEOF2'
import json, sys
out, img, net = sys.argv[1:4]
labels = {"whalewall.enabled": "true", "whalewall.rules": "# " + "x" * 1100000}
body = {
    "Image": img, "Entrypoint": ["sleep"], "Cmd": ["infinity"], "Labels": labels,
    "HostConfig": {"NetworkMode": net, "Dns": ["192.0.2.53"]},
    "NetworkingConfig": {"EndpointsConfig": {net: {"IPAMConfig": {"IPv4Address": "10.99.0.191"}}}},
}
json.dump(body, open(out, "w"))
PYEOF2
	curl -sS --unix-socket /var/run/docker.sock -X POST -H 'Content-Type: application/json' --data @"$OUT/big.json" "http://localhost/containers/create?name=hb2" >/dev/null
	docker start hb2 >/dev/null
	wait_rules hb2
	ww_log_excerpt 'invalid rules.*hb2' 1
	assert_contains "larger than" "an oversized label is rejected"
	curl_in hb2 "$WEBA"
	assert_fail "the container is isolated"

	start_client hb3 10.99.0.192 "$(rules '["a.corp.test"]')
---
output:
  - ips: [0.0.0.0/0]
    proto: tcp
    dst_ports: [1-65535]" --dns "$DUMMY_DNS"
	ww_log_excerpt 'more than one YAML document.*hb3' 1
	assert_contains "only the first is used" "a second YAML document is reported and ignored"
	curl_in hb3 "http://a.corp.test:8080/"
	assert_contains "hello from web-a" "the first document applies"
	curl_in hb3 "$WEBB"
	assert_fail "the second document did not widen the rules"

	say "whalewall still manages new containers right away"
	start_client hb4 10.99.0.193 "$(rules '["a.corp.test"]')" --dns "$DUMMY_DNS"
	curl_in hb4 "http://a.corp.test:8080/"
	assert_contains "hello from web-a" "a well formed container works"
	hostsh "kill -0 $WW_PID && echo whalewall is running"
	assert_contains "whalewall is running" "whalewall is running"
	rm_containers hb1 hb2 hb3 hb4
	sc_end
}

s37() {
	sc_begin 37 host-settings "Host settings the filtering depends on are checked"
	hostsh "cat /proc/sys/net/bridge/bridge-nf-call-iptables"
	assert_contains "1" "bridge-nf-call-iptables is 1, so traffic between containers is filtered"
	hostsh "cat /proc/sys/net/netfilter/nf_conntrack_helper 2>/dev/null || echo 0"
	assert_eq "$LAST_OUT" 0 "connection tracking helpers are off"
	say "whalewall does not warn when the settings are right"
	hostsh "grep -c 'br_netfilter kernel module is not loaded\|nf_conntrack_helper is 1' $OUT/whalewall.log"
	assert_eq "$LAST_OUT" 0 "no kernel setting warnings in the log"
	sc_end
}

s38() {
	sc_begin 38 shared-network "Containers that share another container's network are filtered by that container's rules"
	start_client ns-owner 10.99.0.200 "$(rules '["a.corp.test"]')" --dns "$DUMMY_DNS"
	say "an unmanaged container uses the network of a managed one"
	docker rm -f ns-side >/dev/null 2>&1
	run docker run -d --name ns-side --network container:ns-owner --entrypoint sleep "$IMG" infinity
	curl_in ns-side "http://a.corp.test:8080/"
	assert_contains "hello from web-a" "the sidecar can reach what the owner is allowed to reach"
	curl_in ns-side "$WEBB"
	assert_fail "the sidecar can not reach anything else, it has the owner's address and so its rules"
	rm_containers ns-side ns-owner

	say "a managed container is limited to web-a by its rules but uses the network of an unmanaged one (Docker does not allow the dns option together with this)"
	start_plain ns-plain 10.99.0.201
	docker rm -f ns-bad >/dev/null 2>&1
	run docker run -d --name ns-bad --network container:ns-plain --entrypoint sleep -l whalewall.enabled=true -l "whalewall.rules=output:
  - ips: [10.99.0.10]
    proto: tcp
    dst_ports: [8080]" "$IMG" infinity
	sleep 2
	ww_log_excerpt 'has no network of its own.*ns-bad|ns-bad.*has no network of its own' 1
	assert_contains "no network of its own" "whalewall reports that the rules of the container can not be applied"
	say "KNOWN LIMITATION: the rules of ns-bad are not applied, its traffic uses the unmanaged address of ns-plain"
	curl_in ns-bad "$WEBB"
	assert_contains "hello from web-b" "ns-bad is not restricted by its own rules"
	rm_containers ns-bad ns-plain
	sc_end
}

s39() {
	sc_begin 39 legacy-defaults "Without the new flags whalewall behaves as before"
	say "whalewall is restarted with no flags at all"
	ww_stop
	WW_LEGACY=1 ww_start -t 10s

	say "invalid rules: the container gets no rules and is not restricted, an error is logged"
	start_client lg1 10.99.0.210 'output:
  - bogus: true' || true
	ww_log_excerpt 'lg1' 3
	assert_contains "error" "an error is logged"
	curl_in lg1 "$WEBB"
	assert_contains "hello from web-b" "the container is not restricted (as before)"
	hostsh "nft list ruleset 2>/dev/null | grep -c whalewall-lg1 || true"
	assert_eq "$LAST_OUT" 0 "no chain was created for it"

	say "valid rules work as before"
	start_client lg2 10.99.0.211 'output:
  - ips: ["10.99.0.10"]
    proto: tcp
    dst_ports: [8080]'
	curl_in lg2 "$WEBA"
	assert_contains "hello from web-a" "the allowed address is reachable"
	curl_in lg2 "$WEBB"
	assert_fail "everything else is dropped"

	say "domain rules need -dns, as the label is only understood with it"
	start_client lg3 10.99.0.212 "$(rules '["a.corp.test"]')" --dns "$DUMMY_DNS" || true
	curl_in lg3 "$WEBB"
	assert_contains "hello from web-b" "without -dns the rules are rejected and the container is left alone, like any invalid rules"

	if has_v6; then
		say "IPv6 is left alone without -ipv6"
		hostsh "nft list table ip6 filter 2>/dev/null | grep -c 'whalewall-lg2' || true"
		assert_eq "$LAST_OUT" 0 "no IPv6 chain exists for a container with an IPv6 address"
		ww_log_excerpt 'IPv6 traffic is not managed' 1
		assert_contains "-ipv6" "whalewall says how to manage IPv6"
	fi
	rm_containers lg1 lg2 lg3
	ww_stop
	ww_start
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
for n in 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21 22 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 23; do
	want "$n" && "s$n"
done

echo
echo "passed: $PASS_COUNT  failed: $FAIL_COUNT  skipped: $SKIP_COUNT"
[ "$FAIL_COUNT" = 0 ]
