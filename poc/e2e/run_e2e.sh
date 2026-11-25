#!/usr/bin/env bash
# End-to-end check of the real plugin inside a real CLIProxyAPI process.
# Requires: CPA binary at $CPA_BIN, mock upstream on :18081 (with /v1/moderations),
# CPA started from this directory with OPENAI_MODERATION_API_KEY=test-moderation-key.
set -u
BASE=http://127.0.0.1:18318
MG="$BASE/v0/management/plugins/cpa-moderation"
AUTH="Authorization: Bearer e2e-mgmt-secret"
K1="sk-poc-image-business"; K2="sk-poc-other"
PNG_B64="iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
PASS=0; FAIL=0

check() { # name expected_code actual_code [body]
  if [ "$2" = "$3" ]; then PASS=$((PASS+1)); echo "PASS $1 ($3)"; else FAIL=$((FAIL+1)); echo "FAIL $1: want $2 got $3 :: ${4:0:300}"; fi
}
# Counts generation calls only (the mock also serves /v1/moderations).
upstream_hits() { grep "$1" upstream.jsonl 2>/dev/null | grep -vc '"/v1/moderations' || true; }
req() { # -> sets CODE and BODY
  local out; out=$(curl -s -m 30 -w $'\n%{http_code}' "$@"); CODE="${out##*$'\n'}"; BODY="${out%$'\n'*}"
}
# The body goes through a UTF-8 file: Windows curl re-encodes non-ASCII argv.
chat() {
  python -I -c "import json,sys;open('body.json','w',encoding='utf-8').write(json.dumps({'model':sys.argv[1],'messages':[{'role':'user','content':sys.argv[2]}]},ensure_ascii=False))" "$2" "$3"
  req -X POST $BASE/v1/chat/completions -H "Authorization: Bearer $1" -H "Content-Type: application/json; charset=utf-8" --data-binary @body.json
}

# --- management: status, key sync, policy ---
req "$MG/status" -H "$AUTH"; check "mgmt status" 200 "$CODE" "$BODY"
echo "    $BODY" | head -c 400; echo
req -X POST "$MG/keys/sync" -H "$AUTH" -H "Content-Type: application/json" -d "{\"keys\":[\"$K1\",\"$K2\"]}"
check "mgmt keys/sync" 200 "$CODE" "$BODY"
REV=$(printf '%s' "$BODY" | python -I -c "import json,sys;print(json.load(sys.stdin)['revision'])")
S1=$(python -I -c "import hashlib;print(hashlib.sha256(b'cli-proxy-api:caller-scope:v1\x00$K1').hexdigest())")
S2=$(python -I -c "import hashlib;print(hashlib.sha256(b'cli-proxy-api:caller-scope:v1\x00$K2').hexdigest())")
STATE=$(cat <<EOF
{"revision":$REV,
 "rules":[{"id":"image-business","name":"生图业务","enabled":true,"models":["gpt-image-*","gpt-6*"],"check_text":true,"check_image":true,"wordlists":["biz"],"unsupported_content":"deny","on_error":"deny"}],
 "wordlists":[{"id":"biz","name":"业务词库","enabled":true,"keywords":["SYNTHETICBANNED","合成测试禁词"],"regex":[]}],
 "keys":[{"scope":"$S1","preview":"sk-poc…ness","rule_ids":["image-business"]},{"scope":"$S2","preview":"sk-poc…ther","rule_ids":[]}]}
EOF
)
printf '%s' "$STATE" > state.json
req -X PUT "$MG/state" -H "$AUTH" -H "Content-Type: application/json; charset=utf-8" --data-binary @state.json; check "mgmt put state" 200 "$CODE" "$BODY"
req -X PUT "$MG/state" -H "$AUTH" -H "Content-Type: application/json; charset=utf-8" --data-binary @state.json; check "mgmt stale revision -> 409" 409 "$CODE" "$BODY"
req -X PUT "$MG/state" -d '{}' ; check "mgmt without auth -> 401" 401 "$CODE" "$BODY"
req -X POST "$MG/provider/test" -H "$AUTH"; check "mgmt provider test" 200 "$CODE" "$BODY"
grep -q "$K1" plugins/cpa-moderation-state-v1.json && { FAIL=$((FAIL+1)); echo "FAIL raw key in state file"; } || { PASS=$((PASS+1)); echo "PASS no raw key in state file"; }

# --- traffic ---
chat $K1 gpt-image-1 "clean E2E-01"; check "T01 bound key + matched model, clean" 200 "$CODE" "$BODY"
chat $K2 gpt-image-1 "FLAGME E2E-02"; check "T02 unbound key not moderated" 200 "$CODE" "$BODY"
chat $K1 mock-chat "FLAGME E2E-03"; check "T02 unmatched model not moderated" 200 "$CODE" "$BODY"
chat $K1 friendly-alias "FLAGME E2E-03b"; check "T03 alias name not in rule -> not moderated (documented)" 200 "$CODE" "$BODY"
chat $K1 gpt-6-mini "FLAGME E2E-04"; check "T06 flagged -> 403" 403 "$CODE" "$BODY"
[ "$(upstream_hits E2E-04)" = "0" ] && { PASS=$((PASS+1)); echo "PASS T06 upstream not called"; } || { FAIL=$((FAIL+1)); echo "FAIL T06 upstream called"; }
echo "    $BODY"
chat $K1 gpt-6-mini "has ＳＹＮＴＨＥＴＩＣＢＡＮＮＥＤ E2E-05"; check "T05 wordlist (full-width) -> 403" 403 "$CODE" "$BODY"
chat $K1 gpt-6-mini "合成​测试禁词 E2E-05b"; check "T05 wordlist (zero-width) -> 403" 403 "$CODE" "$BODY"
chat $K1 gpt-6-mini "MODERATION_DOWN E2E-06"; check "T07 moderation down -> 503" 503 "$CODE" "$BODY"
[ "$(upstream_hits E2E-06)" = "0" ] && { PASS=$((PASS+1)); echo "PASS T07 upstream not called"; } || { FAIL=$((FAIL+1)); echo "FAIL T07 upstream called"; }

req -X POST $BASE/v1/chat/completions -H "Authorization: Bearer $K1" -H "Content-Type: application/json" \
  -d '{"model":"gpt-6-mini","stream":true,"messages":[{"role":"user","content":"FLAGME stream E2E-07"}]}'
check "T11 stream flagged -> 403 JSON" 403 "$CODE" "$BODY"
req -X POST $BASE/v1/chat/completions -H "Authorization: Bearer $K1" -H "Content-Type: application/json" \
  -d '{"model":"gpt-6-mini","stream":true,"messages":[{"role":"user","content":"clean stream E2E-08"}]}'
check "T11 stream clean passes" 200 "$CODE" "$BODY"

req -X POST $BASE/v1/messages -H "x-api-key: $K1" -H "anthropic-version: 2023-06-01" -H "Content-Type: application/json" \
  -d '{"model":"claude-mock","max_tokens":8,"messages":[{"role":"user","content":"FLAGME E2E-09"}]}'
check "claude-mock not in rule -> passes" 200 "$CODE" "$BODY"

req -X POST $BASE/v1/responses -H "Authorization: Bearer $K1" -H "Content-Type: application/json" \
  -d '{"model":"gpt-6-mini","instructions":"x","input":[{"role":"user","content":[{"type":"input_text","text":"hi E2E-10"},{"type":"input_image","image_url":"data:image/png;base64,FLAGME'$PNG_B64'"}]}]}'
check "T08 responses with bad base64 image -> 400" 400 "$CODE" "$BODY"
req -X POST $BASE/v1/responses -H "Authorization: Bearer $K1" -H "Content-Type: application/json" \
  -d '{"model":"gpt-6-mini","input":[{"role":"user","content":[{"type":"input_text","text":"history"}]},{"type":"function_call_output","call_id":"c","output":"tool FLAGME E2E-11"}]}'
check "T08 responses tool output flagged -> 403" 403 "$CODE" "$BODY"

req -X POST $BASE/v1/images/generations -H "Authorization: Bearer $K1" -H "Content-Type: application/json" \
  -d '{"model":"gpt-image-1","prompt":"mountain E2E-12"}'
check "T09 images generation clean" 200 "$CODE" "$BODY"
req -X POST $BASE/v1/images/generations -H "Authorization: Bearer $K1" -H "Content-Type: application/json" \
  -d '{"model":"gpt-image-1","prompt":"FLAGME E2E-13"}'
check "T09 images generation flagged -> 403" 403 "$CODE" "$BODY"
printf '%s' "$PNG_B64" | python -I -c "import base64,sys;open('poc.png','wb').write(base64.b64decode(sys.stdin.read()))"
req -X POST $BASE/v1/images/edits -H "Authorization: Bearer $K1" -F model=gpt-image-1 --form-string "prompt=edit E2E-14" -F "image[]=@poc.png;type=image/png" -F "image[]=@poc.png;type=image/png"
check "T09 multipart edit clean, 2 images" 200 "$CODE" "$BODY"
H=$(grep "E2E-14" upstream.jsonl | head -1 | python -I -c "import json,sys;r=json.loads(sys.stdin.read());print(r['content_type'][:30],r['len'])")
echo "    upstream got: $H"
req -X POST $BASE/v1/images/edits -H "Authorization: Bearer $K1" -F model=gpt-image-1 --form-string "prompt=FLAGME E2E-15" -F "image=@poc.png;type=image/png"
check "T09 multipart edit flagged -> 403" 403 "$CODE" "$BODY"

req -X POST $BASE/v1/chat/completions -H "Authorization: Bearer $K1" -H "Content-Type: application/json" \
  -d '{"model":"gpt-6-mini","messages":[{"role":"user","content":[{"type":"input_audio","input_audio":{"data":"AA","format":"wav"}}]}]}'
check "T10 audio unsupported -> 400" 400 "$CODE" "$BODY"
req -X POST "$BASE/v1beta/models/gpt-6-mini:generateContent?key=$K1" -H "Content-Type: application/json" \
  -d '{"contents":[{"role":"user","parts":[{"text":"FLAGME gemini E2E-16"}]}]}'
check "gemini route + query key flagged -> 403" 403 "$CODE" "$BODY"
echo "    $BODY"
chat sk-wrong gpt-6-mini "FLAGME E2E-17"; check "T04 bad key -> 401 before plugin" 401 "$CODE" "$BODY"

# simulate (no forwarding)
req -X POST "$MG/simulate" -H "$AUTH" -H "Content-Type: application/json" \
  -d "{\"key\":\"$K1\",\"model\":\"gpt-image-1\",\"format\":\"openai\",\"body\":{\"messages\":[{\"role\":\"user\",\"content\":\"SYNTHETICBANNED E2E-18\"}]}}"
check "simulate" 200 "$CODE" "$BODY"; echo "    $BODY" | head -c 300; echo
[ "$(upstream_hits E2E-18)" = "0" ] && { PASS=$((PASS+1)); echo "PASS simulate did not forward"; } || { FAIL=$((FAIL+1)); echo "FAIL simulate forwarded"; }

req "$MG/events?limit=3" -H "$AUTH"; check "events" 200 "$CODE" "$BODY"
for leak in FLAGME SYNTHETIC "$K1" mountain; do
  if grep -q "$leak" plugins/cpa-moderation-audit.jsonl; then FAIL=$((FAIL+1)); echo "FAIL audit leaks $leak"; else PASS=$((PASS+1)); echo "PASS audit has no '$leak'"; fi
done
req "$MG/status" -H "$AUTH"; echo "    status: $BODY" | head -c 500; echo
echo "TOTAL pass=$PASS fail=$FAIL"
