#!/usr/bin/env bash
# Upgrade test: rules created by an older whalewall binary keep working
# when the current one takes over, and nothing is duplicated or left
# behind. Needs root, Docker and nft.
#
#   e2e/upgrade.sh <old whalewall binary>
#
# The old binary is usually built from the commit before the changes:
#   git worktree add /tmp/ww-old origin/master
#   (cd /tmp/ww-old && CGO_ENABLED=0 go build -o /tmp/ww-old-bin ./cmd/whalewall)
set -u

cd "$(dirname "$0")/.."
ROOT=$PWD
OLD=${1:?usage: e2e/upgrade.sh <old whalewall binary>}
NEW=$ROOT/e2e/bin/whalewall
IMG=${E2E_IMAGE:-ghcr.io/capnspacehook/eavesdropper}
NET=upgnet
OUT=${E2E_OUT:-$ROOT/e2e/out-upgrade}
FAILS=0
PASSES=0

pass() { echo "PASS  $*"; PASSES=$((PASSES + 1)); }
fail() { echo "FAIL  $*"; FAILS=$((FAILS + 1)); }
check() { # check <description> <command...>
	local desc=$1
	shift
	if "$@" >/dev/null 2>&1; then pass "$desc"; else fail "$desc"; fi
}
check_not() {
	local desc=$1
	shift
	if "$@" >/dev/null 2>&1; then fail "$desc"; else pass "$desc"; fi
}

WW_PID=
start_ww() { # start_ww <binary> <log>
	"$1" -debug -d "$OUT/data" -l "$2" >>"$OUT/stdout" 2>&1 &
	WW_PID=$!
	sleep 2
}
stop_ww() {
	[ -n "$WW_PID" ] || return 0
	kill -TERM "$WW_PID" 2>/dev/null
	wait "$WW_PID" 2>/dev/null
	WW_PID=
}

cleanup() {
	stop_ww
	docker rm -f upg-srv upg-cli upg-ext >/dev/null 2>&1
	docker network rm "$NET" >/dev/null 2>&1
	"$NEW" -clear -d "$OUT/data" >/dev/null 2>&1
}
trap cleanup EXIT

rm -rf "$OUT"
mkdir -p "$OUT/data"
[ -x "$NEW" ] || CGO_ENABLED=0 go build -o "$NEW" ./cmd/whalewall || exit 1
[ -x e2e/bin/web ] || CGO_ENABLED=0 go build -o e2e/bin/web ./e2e/tools/web || exit 1

docker rm -f upg-srv upg-cli upg-ext >/dev/null 2>&1
docker network rm "$NET" >/dev/null 2>&1
docker network create --subnet 10.97.0.0/24 "$NET" >/dev/null || exit 1

web() { # web <name> <ip> [docker flags...]
	local name=$1 ip=$2
	shift 2
	docker run -d --name "$name" --network "$NET" --ip "$ip" -v "$ROOT/e2e/bin:/e2e:ro" --entrypoint /e2e/web "$@" "$IMG" -name "$name" >/dev/null
}

CLI_RULES="output:
  - network: $NET
    container: upg-srv
    proto: tcp
    dst_ports: [8080]
  - proto: udp
    dst_ports: [53]
    log_prefix: dns"

web upg-ext 10.97.0.20
start_ww "$OLD" "$OUT/old.log"
web upg-srv 10.97.0.10 -l whalewall.enabled=true
sleep 2
docker run -d --name upg-cli --network "$NET" --ip 10.97.0.11 --entrypoint sleep \
	-l whalewall.enabled=true -l "whalewall.rules=$CLI_RULES" -v "$ROOT/e2e/bin:/e2e:ro" "$IMG" infinity >/dev/null
sleep 3

get() { docker exec "$1" curl -sS -m 3 --connect-timeout 2 "$2"; }

echo "# rules created by the old binary"
check "old: the container rule lets upg-cli reach upg-srv" get upg-cli http://10.97.0.10:8080/
check_not "old: upg-cli can not reach the unmanaged upg-ext" get upg-cli http://10.97.0.20:8080/
check_not "old: upg-srv can not reach upg-ext" get upg-srv http://10.97.0.20:8080/

snapshot() {
	nft list table ip filter | sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter/; s/ # handle [0-9]+//' | sort
}
snapshot >"$OUT/old.rules"
OLD_WW_LINES=$(grep -c whalewall "$OUT/old.rules")

echo "# the old binary stops, the rules stay"
stop_ww
check "rules of the old binary stay in place" get upg-cli http://10.97.0.10:8080/

echo "# the current binary takes over"
start_ww "$NEW" "$OUT/new.log"
check "new: upg-cli still reaches upg-srv" get upg-cli http://10.97.0.10:8080/
check_not "new: upg-cli still can not reach upg-ext" get upg-cli http://10.97.0.20:8080/
check_not "new: upg-srv still can not reach upg-ext" get upg-srv http://10.97.0.20:8080/
snapshot >"$OUT/new.rules"
if diff -u "$OUT/old.rules" "$OUT/new.rules" >"$OUT/rules.diff"; then
	pass "the rules are identical after the takeover ($OLD_WW_LINES whalewall lines)"
else
	fail "the rules changed after the takeover, see $OUT/rules.diff"
	head -n 30 "$OUT/rules.diff"
fi
check_not "the current binary logged no errors for the takeover" grep -q '"level":"error"' "$OUT/new.log"

echo "# a container started by the old binary is cleaned up by the current one"
docker rm -f upg-cli >/dev/null
sleep 3
check_not "the chain of the removed container is gone" sh -c 'nft list ruleset | grep -q whalewall-upg-cli'
check "upg-srv is still managed" sh -c 'nft list ruleset | grep -q whalewall-upg-srv'

echo "# the current binary creates rules the same way"
docker run -d --name upg-cli --network "$NET" --ip 10.97.0.11 --entrypoint sleep \
	-l whalewall.enabled=true -l "whalewall.rules=$CLI_RULES" -v "$ROOT/e2e/bin:/e2e:ro" "$IMG" infinity >/dev/null
sleep 3
check "new: a fresh upg-cli reaches upg-srv" get upg-cli http://10.97.0.10:8080/
check_not "new: a fresh upg-cli can not reach upg-ext" get upg-cli http://10.97.0.20:8080/
snapshot >"$OUT/new2.rules"
if diff -q "$OUT/old.rules" "$OUT/new2.rules" >/dev/null || [ "$(grep -c whalewall "$OUT/new2.rules")" = "$OLD_WW_LINES" ]; then
	pass "the new binary creates as many whalewall rules as the old one"
else
	fail "different number of whalewall rule lines: old $OLD_WW_LINES, new $(grep -c whalewall "$OUT/new2.rules")"
fi

echo "# the current binary clears everything"
docker rm -f upg-cli upg-srv >/dev/null
sleep 3
stop_ww
"$NEW" -clear -d "$OUT/data" >/dev/null 2>&1
check_not "nothing of whalewall is left" sh -c 'nft list ruleset 2>/dev/null | grep -q "whalewall\|ww-"'

echo
echo "passed: $PASSES  failed: $FAILS"
[ "$FAILS" = 0 ]
