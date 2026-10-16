#!/usr/bin/env bash
# Helpers for the end-to-end scenarios. Every scenario writes a log to
# $OUT/NN-name.log which render.mjs turns into a screenshot.

IMG=${E2E_IMAGE:-ghcr.io/capnspacehook/eavesdropper}
NET=e2enet
SUBNET4=10.99.0.0/24
GW4=10.99.0.1
SUBNET6=fd00:99::/64
GW6=fd00:99::1
# a documentation address nothing listens on; whalewall redirects all DNS
# traffic of containers with domain rules, so any address works
DUMMY_DNS=192.0.2.53

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

log() { printf '%s\n' "$*" >>"$LOG"; }

sc_begin() {
	SC_NUM=$1 SC_NAME=$2 SC_TITLE=$3
	LOG="$OUT/$SC_NUM-$SC_NAME.log"
	: >"$LOG"
	SC_FAILED=0
	log "TITLE $SC_NUM  $SC_TITLE"
	echo "=== $SC_NUM $SC_NAME: $SC_TITLE"
}

# say prints a commentary line.
say() { log "# $*"; }

# run executes a command on the host and logs it.
run() {
	log "\$ $*"
	LAST_OUT=$("$@" 2>&1)
	LAST_RC=$?
	[ -n "$LAST_OUT" ] && log "$LAST_OUT"
	log "[exit $LAST_RC]"
	return 0
}

# cexec runs a shell command inside a container and logs it.
cexec() {
	local c=$1
	shift
	log "[$c]\$ $*"
	LAST_OUT=$(docker exec "$c" sh -c "$*" 2>&1)
	LAST_RC=$?
	[ -n "$LAST_OUT" ] && log "$LAST_OUT"
	log "[exit $LAST_RC]"
	return 0
}

# hostsh runs a shell snippet on the host and logs it.
hostsh() {
	log "\$ $*"
	LAST_OUT=$(sh -c "$*" 2>&1)
	LAST_RC=$?
	[ -n "$LAST_OUT" ] && log "$LAST_OUT"
	log "[exit $LAST_RC]"
	return 0
}

pass() { log "PASS  $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() {
	log "FAIL  $*"
	FAIL_COUNT=$((FAIL_COUNT + 1))
	SC_FAILED=1
}

assert_rc() { # assert_rc <rc> <description>
	if [ "$LAST_RC" = "$1" ]; then pass "$2"; else fail "$2 (exit $LAST_RC, wanted $1)"; fi
}
assert_fail() { # assert_fail <description>: last command failed
	if [ "$LAST_RC" != 0 ]; then pass "$1"; else fail "$1 (command succeeded)"; fi
}
assert_contains() { # assert_contains <text> <description>
	if printf '%s' "$LAST_OUT" | grep -qF -- "$1"; then pass "$2"; else fail "$2 (output lacks \"$1\")"; fi
}
assert_not_contains() {
	if printf '%s' "$LAST_OUT" | grep -qF -- "$1"; then fail "$2 (output has \"$1\")"; else pass "$2"; fi
}
assert_eq() { # assert_eq <got> <want> <description>
	if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (got \"$1\", wanted \"$2\")"; fi
}

sc_skip() {
	log "SKIP  $1"
	SKIP_COUNT=$((SKIP_COUNT + 1))
	log "RESULT SKIP"
	echo "    skipped: $1"
}

# seccomp_events prints how many seccomp violations were recorded for
# the whalewall binary since the run started.
seccomp_events() {
	dmesg 2>/dev/null | awk -v exe="exe=\"$WW\"" -v start="$RUN_START" '
		/type=1326/ && index($0, exe) {
			match($0, /audit\([0-9]+/)
			if (substr($0, RSTART + 6, RLENGTH - 6) >= start) n++
		}
		END { print n + 0 }'
}

sc_end() {
	echo "    seccomp violations so far: $(seccomp_events)"
	if [ "$SC_FAILED" = 0 ]; then
		log "RESULT PASS"
		echo "    PASS"
	else
		log "RESULT FAIL"
		echo "    FAIL (see $LOG)"
	fi
}

# fakedns_queries <name> prints how many queries for name reached the
# fake upstream.
fakedns_queries() {
	grep -c " $1\. " "$OUT/queries.log" 2>/dev/null || true
}

# ww_log_excerpt <pattern> logs matching whalewall log lines, shortened.
ww_log_excerpt() {
	log "\$ grep '$1' whalewall.log"
	local out
	out=$(grep -E -- "$1" "$OUT/whalewall.log" | tail -n "${2:-3}" |
		sed -E 's/"time":"[^"]*",//; s/"container.id":"[^"]*",//' | cut -c1-230)
	LAST_OUT=$out
	[ -n "$out" ] && log "$out"
	return 0
}

start_count() {
	local n
	n=$(grep -c '"msg":"starting whalewall"' "$OUT/whalewall.log" 2>/dev/null || true)
	echo "${n:-0}"
}

# ww_start [flags...] starts whalewall with DNS filtering.
ww_start() {
	local flags=("$@")
	if [ "${#flags[@]}" = 0 ]; then
		flags=(-dns -dns-upstream 127.0.0.1:5300 -dns-min-ttl 1s -dns-grace 1s)
	fi
	local started
	started=$(start_count)
	"$WW" "${flags[@]}" -debug -d "$OUT/data" -l "$OUT/whalewall.log" >>"$OUT/whalewall.stdout" 2>&1 &
	WW_PID=$!
	local i
	for i in $(seq 1 50); do
		[ "$(start_count)" -gt "$started" ] && return 0
		sleep 0.1
	done
	echo "whalewall did not start:" >&2
	tail -n 5 "$OUT/whalewall.stdout" >&2
	return 1
}

ww_stop() {
	[ -n "${WW_PID:-}" ] || return 0
	kill -TERM "$WW_PID" 2>/dev/null || true
	wait "$WW_PID" 2>/dev/null || true
	WW_PID=
}

# start_client <name> <ipv4> <rules> [docker run flags...] starts a managed
# container that sleeps. The rules label is omitted if rules is "-".
start_client() {
	local name=$1 ip=$2 rules=$3
	shift 3
	local args=(--network "$NET" --ip "$ip" --entrypoint sleep -l whalewall.enabled=true)
	if [ "$E2E_IPV6" = 1 ]; then
		args+=(--ip6 "fd00:99::${ip##*.}")
	fi
	[ "$rules" != "-" ] && args+=(-l "whalewall.rules=$rules")
	docker rm -f "$name" >/dev/null 2>&1
	docker run -d --name "$name" "${args[@]}" "$@" "$IMG" infinity >/dev/null
	wait_rules "$name"
}

# start_plain <name> <ipv4> [docker run flags...] starts an unmanaged
# container that sleeps.
start_plain() {
	local name=$1 ip=$2
	shift 2
	local args=(--network "$NET" --ip "$ip" --entrypoint sleep)
	if [ "$E2E_IPV6" = 1 ]; then
		args+=(--ip6 "fd00:99::${ip##*.}")
	fi
	docker rm -f "$name" >/dev/null 2>&1
	docker run -d --name "$name" "${args[@]}" "$@" "$IMG" infinity >/dev/null
}

cid() { docker inspect -f '{{.Id}}' "$1" | cut -c1-12; }

# wait_rules <name> waits until whalewall created rules for a container.
wait_rules() {
	local name=$1 id i
	id=$(cid "$name")
	for i in $(seq 1 100); do
		if nft list chain ip filter "whalewall-$name-$id" >/dev/null 2>&1 &&
			grep -q "adding to database\|error" <(grep "$id" "$OUT/whalewall.log" 2>/dev/null); then
			sleep 0.3
			return 0
		fi
		sleep 0.1
	done
	echo "rules for $name were not created" >&2
	return 1
}

rm_containers() {
	local c
	for c in "$@"; do
		docker rm -f "$c" >/dev/null 2>&1 || true
	done
}

# set_elements <container> <rule index> [4|6] logs the contents of a
# container's domain set.
set_elements() {
	local fam=ip
	[ "${3:-4}" = 6 ] && fam=ip6
	hostsh "nft list set $fam filter ww-$(cid "$1")-$2-${3:-4}"
}

# curl_in <container> <url> logs a curl run inside a container.
curl_in() {
	cexec "$1" "curl -sS -m 4 --connect-timeout 2 $2"
}
