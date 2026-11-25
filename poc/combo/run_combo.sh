#!/usr/bin/env bash
# cpa-moderation + cpa-key-billing loaded together in one CLIProxyAPI.
# Usage (from poc/combo, CPA on :18319, mock on :18082): bash run_combo.sh <billing-first|moderation-first>
set -u
ORDER="${1:-billing-first}"
BASE=http://127.0.0.1:18319
AUTH="Authorization: Bearer combo-mgmt-secret"
MOD="$BASE/v0/management/plugins/cpa-moderation"
BILL="$BASE/v0/management/plugins/cpa-key-billing"
K1="sk-poc-image-business"; K2="sk-poc-other"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "PASS $1"; }
bad()  { FAIL=$((FAIL+1)); echo "FAIL $1"; }
check() { [ "$2" = "$3" ] && ok "$1 ($3)" || bad "$1: want $2 got $3 :: ${4:0:240}"; }
req() { local out; out=$(curl -s -m 30 -w $'\n%{http_code}' "$@"); CODE="${out##*$'\n'}"; BODY="${out%$'\n'*}"; }
gen_hits() { grep "$1" upstream.jsonl 2>/dev/null | grep -vc '"/v1/moderations' || true; }
mod_hits() { grep "$1" upstream.jsonl 2>/dev/null | grep -c '"/v1/moderations' || true; }
chat() { # key model text [extra curl args]
  python -I -c "import json,sys;open('body-'+sys.argv[3]+'.json','w',encoding='utf-8').write(json.dumps({'model':sys.argv[1],'messages':[{'role':'user','content':sys.argv[2]}]}))" "$2" "$3" "$$-$RANDOM" 2>/dev/null
  local f; f=$(ls -t body-*.json | head -1)
  req -X POST $BASE/v1/chat/completions -H "Authorization: Bearer $1" -H "Content-Type: application/json" --data-binary @"$f"
  rm -f "$f"
}
billing_events() { # number of billed request events for K1's scope
  curl -s "$BILL/events?limit=500" -H "$AUTH" | python -I -c "
import json,sys
print(json.load(sys.stdin)['total'])"
}
S1=$(python -I -c "import hashlib;print(hashlib.sha256(b'cli-proxy-api:caller-scope:v1\x00$K1').hexdigest())")

echo "== order: $ORDER"
grep -E "plugin registered" cpa.log | sed 's/.*plugin_id=/  registered: /'

# --- moderation policy: K1 x gpt-6* ---
req -X POST "$MOD/keys/sync" -H "$AUTH" -H "Content-Type: application/json" -d "{\"keys\":[\"$K1\",\"$K2\"]}"
REV=$(printf '%s' "$BODY" | python -I -c "import json,sys;print(json.load(sys.stdin)['revision'])")
cat > state.json <<EOF
{"revision":$REV,"rules":[{"id":"r1","name":"r1","enabled":true,"models":["gpt-6*"],"check_text":true,"check_image":true,"unsupported_content":"deny","on_error":"deny"}],
 "wordlists":[],"keys":[{"scope":"$S1","preview":"k1","rule_ids":["r1"]}]}
EOF
req -X PUT "$MOD/state" -H "$AUTH" -H "Content-Type: application/json" --data-binary @state.json
check "moderation policy saved" 200 "$CODE" "$BODY"

# --- billing: sync keys, concurrency limit 1 for K1 ---
req -X POST "$BILL/keys/sync" -H "$AUTH" -H "Content-Type: application/json" -d "{\"keys\":[\"$K1\",\"$K2\"],\"allow_empty\":true}"
check "billing keys synced" 200 "$CODE" "$BODY"
req -X POST "$BILL/keys/concurrency" -H "$AUTH" -H "Content-Type: application/json" -d "{\"scope\":\"$S1\",\"concurrency_limit\":1}"
check "billing concurrency=1 for K1" 200 "$CODE" "$BODY"

E0=$(billing_events)
chat $K1 gpt-6-mini "clean C-01"; check "clean request passes both plugins" 200 "$CODE" "$BODY"
sleep 1; E1=$(billing_events)
[ "$E1" -gt "$E0" ] && ok "clean request was billed ($E0 -> $E1)" || bad "clean request not billed ($E0 -> $E1)"

chat $K1 gpt-6-mini "FLAGME C-02"; check "flagged request blocked" 403 "$CODE" "$BODY"
printf '%s' "$BODY" | grep -q content_policy_violation && ok "403 comes from cpa-moderation" || bad "403 not from moderation: $BODY"
[ "$(gen_hits C-02)" = "0" ] && ok "flagged request never reached upstream" || bad "flagged request reached upstream"
sleep 1; E2=$(billing_events)
[ "$E2" = "$E1" ] && ok "blocked request was not billed ($E2)" || bad "blocked request billed ($E1 -> $E2)"

# Slot leak check: with concurrency 1, any slot leaked by a blocked request would turn the next clean request into 429.
for i in 1 2 3 4 5; do chat $K1 gpt-6-mini "FLAGME C-03-$i" >/dev/null; done
chat $K1 gpt-6-mini "clean C-04"; check "after 5 blocked requests, clean request still admitted (no slot leak)" 200 "$CODE" "$BODY"

# Ordering probe: hold K1's only slot with a slow upstream call, then send a flagged request concurrently.
chat $K1 gpt-6-mini "SLOW_UPSTREAM C-05" &
HOLD=$!
sleep 1.2
chat $K1 gpt-6-mini "FLAGME C-06"
C06_CODE=$CODE; C06_BODY=$BODY
wait $HOLD
if [ "$ORDER" = "billing-first" ]; then
  check "billing runs first: concurrent request refused by billing" 429 "$C06_CODE" "$C06_BODY"
  [ "$(mod_hits C-06)" = "0" ] && ok "moderation API not called for billing-refused request" || bad "moderation called although billing refused"
else
  check "moderation runs first: concurrent flagged request refused by moderation" 403 "$C06_CODE" "$C06_BODY"
  printf '%s' "$C06_BODY" | grep -q content_policy_violation && ok "refusal is moderation's" || bad "refusal not moderation's: $C06_BODY"
fi
chat $K1 gpt-6-mini "clean C-07"; check "slot free again after slow request" 200 "$CODE" "$BODY"

# Unbound key / unmatched model: billing still applies, moderation skips.
chat $K2 gpt-6-mini "FLAGME C-08"; check "unbound key not moderated, billing still passes" 200 "$CODE" "$BODY"
chat $K1 mock-chat "FLAGME C-09"; check "unmatched model not moderated" 200 "$CODE" "$BODY"
[ "$(mod_hits C-08)" = "0" ] && [ "$(mod_hits C-09)" = "0" ] && ok "moderation API not called for skipped requests" || bad "moderation called for skipped requests"

# Both management APIs and UIs coexist.
for p in "$MOD/status" "$BILL/keys"; do req "$p" -H "$AUTH"; check "mgmt $p" 200 "$CODE" "$BODY"; done
for p in cpa-moderation cpa-key-billing; do req "$BASE/v0/resource/plugins/$p/ui"; check "ui $p" 200 "$CODE" ""; done

echo "TOTAL pass=$PASS fail=$FAIL"
