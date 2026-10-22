#!/usr/bin/env bash
# End-to-end, process-level: two real TLS pyles + real HTTP clients.
# Requires a prior `cargo build --workspace` (cargo test does not rebuild the
# target/debug binaries this script launches).
set -uo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
BIN="$ROOT/target/debug"
A=18443
B=18444
TMP="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

echo "[e2e] tmp=$TMP"
"$BIN/hdap-server" --listen 127.0.0.1:$A --open-federation --data "$TMP/A" --choregia 1048576 >"$TMP/A.log" 2>&1 &
"$BIN/hdap-server" --listen 127.0.0.1:$B --open-federation --data "$TMP/B" --choregia 1048576 >"$TMP/B.log" 2>&1 &
for _ in $(seq 1 100); do
  PA=$(grep -oE 'tls_pin=[0-9a-f]{64}' "$TMP/A.log" 2>/dev/null | head -1 | cut -d= -f2)
  PB=$(grep -oE 'tls_pin=[0-9a-f]{64}' "$TMP/B.log" 2>/dev/null | head -1 | cut -d= -f2)
  [[ -n "$PA" && -n "$PB" ]] && break
  sleep 0.1
done
[[ -n "${PA:-}" && -n "${PB:-}" ]] || { cat "$TMP/A.log" "$TMP/B.log"; fail "servers did not boot"; }
ID_A=$(curl -sk "https://127.0.0.1:$A/health" | python3 -c 'import sys,json;print(json.load(sys.stdin)["server_id"])')
ID_B=$(curl -sk "https://127.0.0.1:$B/health" | python3 -c 'import sys,json;print(json.load(sys.stdin)["server_id"])')
echo "[e2e] A=$ID_A  B=$ID_B"

cli() { "$BIN/hdap-cli" --pass pw "$@"; }
A_cli() { cli --home "$TMP/alice" --host 127.0.0.1 --port $A --tls-pin "$PA" "$@"; }
B_cli() { cli --home "$TMP/bob" --host 127.0.0.1 --port $B --tls-pin "$PB" "$@"; }

mkdir -p "$TMP/alice" "$TMP/bob"
A_cli init alice >/dev/null
B_cli init bob >/dev/null
ALICE=$(A_cli register | grep -oE 'registered \S+' | cut -d' ' -f2)
BOB=$(B_cli register | grep -oE 'registered \S+' | cut -d' ' -f2)
[[ -n "$ALICE" && -n "$BOB" ]] || fail "register"
echo "[e2e] alice=$ALICE  bob=$BOB"

TA=$(A_cli auth | grep -oE '[0-9a-f]{64}' | head -1)
TB=$(B_cli auth | grep -oE '[0-9a-f]{64}' | head -1)
[[ -n "$TA" && -n "$TB" ]] || fail "auth"
A_cli band "$TA" 20 >/dev/null || fail "band"
ok "alice registered, authed, banded"

echo "conteudo cross-pyle $(date +%s)" > "$TMP/a.txt"
A_cli upload "$TA" "$ALICE" docs/a.txt "$TMP/a.txt" >/dev/null || fail "upload on A"
ok "alice uploaded docs/a.txt on A"

URI="HDAP!$ID_A@$ALICE/docs/a.txt"
RES=$(curl -sk -X POST "https://127.0.0.1:$B/resolve" -H "authorization: Bearer $TB" -d "{\"uri\":\"$URI\"}")
echo "[e2e] resolve -> $RES"
echo "$RES" | grep -q '"status":"mirrored"' || fail "bob could not mirror alice's namespace"
# The source must withhold the private blob until a grant exists: only the
# public config docs (prosopeion + adeia) may cross the wire.
echo "$RES" | grep -q '"copied":2' || fail "source leaked private blobs before the grant (expected copied:2)"
ok "bob mirrored only the public docs onto B (private blob stayed at origin)"

# No grant yet: bob must NOT read.
if B_cli download "$TB" "$ALICE" docs/a.txt "$TMP/deny" >/dev/null 2>&1; then
  fail "bob read without a grant"
fi
ok "bob denied without a grant (403)"

# Alice publishes a read grant for bob through POST /adeia.
ADEIA="# HSYST DESCENTRALIZED ARCHIVE PROTOCOL
## DOC: adeia
### HEAD:
# VERSION: 1
# TYPE: adeia
# EDITION: 1
# CREATED_AT: 1700000000
### :END HEAD
### BODY:
# PERM0000: PERM $ALICE user:$BOB read
### :END BODY
### SIGS:
### :END SIGS
## :END DOC"
CODE=$(curl -sk -o "$TMP/adeia.out" -w '%{http_code}' -X POST "https://127.0.0.1:$A/adeia" \
  -H "authorization: Bearer $TA" --data-binary "$ADEIA")
[[ "$CODE" == "200" ]] || { cat "$TMP/adeia.out"; fail "POST /adeia -> $CODE"; }
ok "alice published a grant to bob via POST /adeia"

RES2=$(curl -sk -X POST "https://127.0.0.1:$B/resolve" -H "authorization: Bearer $TB" -d "{\"uri\":\"$URI\"}")
echo "[e2e] re-resolve -> $RES2"
echo "$RES2" | grep -q '"copied":1' || fail "expected exactly the newly-authorized blob (copied:1), got: $RES2"
B_cli download "$TB" "$ALICE" docs/a.txt "$TMP/got" >/dev/null || fail "bob could not read after the grant"
cmp -s "$TMP/a.txt" "$TMP/got" || fail "content mismatch after cross-pyle read"
ok "bob read alice's file cross-pyle after the grant, byte-identical"

BUB=$(curl -sk "https://127.0.0.1:$B/bubble" -H "authorization: Bearer $TB")
echo "$BUB" | grep -q '"counts"' && echo "$BUB" | grep -q '"tier":"' || { echo "$BUB"; fail "bubble"; }
ok "bob's bubble lists a tiered peer"

HASH=$(sha256sum "$TMP/a.txt" | cut -d' ' -f1)
RH=$(curl -sk -X POST "https://127.0.0.1:$B/resolve_hash" -H "authorization: Bearer $TB" -d "{\"hash\":\"$HASH\"}")
echo "[e2e] resolve_hash -> $RH"
echo "$RH" | grep -q '"status":"local"' || fail "resolve_hash local"
echo "$RH" | grep -q "$HASH" || fail "resolve_hash hash"
ok "resolve_hash serves the mirrored blob by pechys"

# Alice deletes at the origin: the push must remove bob's replica, not leave it
# orphaned forever (the origin recorded bob as a watcher when he pulled).
A_cli delete "$TA" "$ALICE" docs/a.txt >/dev/null || fail "delete on A"
if B_cli download "$TB" "$ALICE" docs/a.txt "$TMP/gone" >/dev/null 2>&1; then
  fail "replica survived deletion at the origin"
fi
ok "delete at the origin removed bob's replica"

echo "ALL PASS"
