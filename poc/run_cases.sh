#!/usr/bin/env bash
# PoC case matrix. Each case tags its payload with CASE-xx so upstream hits can be correlated.
# Usage: bash run_cases.sh [case-filter-regex]   (run from poc/run)
BASE=http://127.0.0.1:18317
K1="sk-poc-image-business"
FILTER="${1:-.}"
PNG_B64="iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
OUT=cases.out
: > "$OUT"

run() { # name, curl args...
  local name="$1"; shift
  [[ "$name" =~ $FILTER ]] || return 0
  local resp code
  resp=$(curl -s -m 30 -w $'\n%{http_code}' "$@")
  code="${resp##*$'\n'}"
  printf '=== %s -> HTTP %s\n%s\n' "$name" "$code" "$(printf '%s' "${resp%$'\n'*}" | head -c 400)" | tee -a "$OUT"
}

j() { echo -H "Content-Type: application/json"; }

run CASE-01-chat-multiturn-image -X POST $BASE/v1/chat/completions -H "Authorization: Bearer $K1" -H "Content-Type: application/json" \
  -d '{"model":"mock-chat","messages":[{"role":"system","content":"sys CASE-01"},{"role":"user","content":"first turn"},{"role":"assistant","content":"reply"},{"role":"user","content":[{"type":"text","text":"look CASE-01"},{"type":"image_url","image_url":{"url":"data:image/png;base64,'$PNG_B64'"}}]}]}'

run CASE-02-chat-stream -X POST $BASE/v1/chat/completions -H "Authorization: Bearer $K1" -H "Content-Type: application/json" \
  -d '{"model":"mock-chat","stream":true,"messages":[{"role":"user","content":"stream CASE-02"}]}'

run CASE-03-alias -X POST $BASE/v1/chat/completions -H "Authorization: Bearer $K1" -H "Content-Type: application/json" \
  -d '{"model":"friendly-alias","messages":[{"role":"user","content":"alias CASE-03"}]}'

run CASE-04-responses -X POST $BASE/v1/responses -H "Authorization: Bearer $K1" -H "Content-Type: application/json" \
  -d '{"model":"mock-chat","instructions":"inst CASE-04","input":[{"role":"user","content":[{"type":"input_text","text":"hi CASE-04"},{"type":"input_image","image_url":"data:image/png;base64,'$PNG_B64'"}]}]}'

run CASE-05-images-gen -X POST $BASE/v1/images/generations -H "Authorization: Bearer $K1" -H "Content-Type: application/json" \
  -d '{"model":"gpt-image-1","prompt":"a mountain CASE-05"}'

printf '%s' "$PNG_B64" | base64 -d > poc.png 2>/dev/null || python -I -c "import base64,sys;open('poc.png','wb').write(base64.b64decode(sys.argv[1]))" "$PNG_B64"
run CASE-06-images-edit-multipart -X POST $BASE/v1/images/edits -H "Authorization: Bearer $K1" \
  -F model=gpt-image-1 --form-string "prompt=edit this CASE-06" -F "image[]=@poc.png;type=image/png" -F "image[]=@poc.png;type=image/png"

run CASE-07-claude-messages-stream -X POST $BASE/v1/messages -H "x-api-key: $K1" -H "anthropic-version: 2023-06-01" -H "Content-Type: application/json" \
  -d '{"model":"claude-mock","max_tokens":16,"stream":true,"system":"sys CASE-07","messages":[{"role":"user","content":[{"type":"text","text":"hi CASE-07"},{"type":"image","source":{"type":"base64","media_type":"image/png","data":"'$PNG_B64'"}}]},{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"f","input":{}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"tool out CASE-07"}]}]}'

run CASE-08-bad-key -X POST $BASE/v1/chat/completions -H "Authorization: Bearer sk-wrong" -H "Content-Type: application/json" \
  -d '{"model":"mock-chat","messages":[{"role":"user","content":"bad key CASE-08"}]}'

run CASE-09-block-chat -X POST $BASE/v1/chat/completions -H "Authorization: Bearer $K1" -H "Content-Type: application/json" \
  -d '{"model":"mock-chat","messages":[{"role":"user","content":"PROBE_BLOCK CASE-09"}]}'

run CASE-10-block-chat-stream -X POST $BASE/v1/chat/completions -H "Authorization: Bearer $K1" -H "Content-Type: application/json" \
  -d '{"model":"mock-chat","stream":true,"messages":[{"role":"user","content":"PROBE_BLOCK CASE-10"}]}'

run CASE-11-block-claude -X POST $BASE/v1/messages -H "x-api-key: $K1" -H "anthropic-version: 2023-06-01" -H "Content-Type: application/json" \
  -d '{"model":"claude-mock","max_tokens":16,"stream":true,"messages":[{"role":"user","content":"PROBE_BLOCK CASE-11"}]}'

run CASE-12-block-images-edit -X POST $BASE/v1/images/edits -H "Authorization: Bearer $K1" \
  -F model=gpt-image-1 --form-string "prompt=PROBE_BLOCK CASE-12" -F "image=@poc.png;type=image/png"

run CASE-13-upstream-500-retry -X POST $BASE/v1/chat/completions -H "Authorization: Bearer $K1" -H "Content-Type: application/json" \
  -d '{"model":"mock-chat","messages":[{"role":"user","content":"UPSTREAM_500 CASE-13"}]}'

run CASE-14-plugin-error -X POST $BASE/v1/chat/completions -H "Authorization: Bearer $K1" -H "Content-Type: application/json" \
  -d '{"model":"mock-chat","messages":[{"role":"user","content":"PROBE_ERROR CASE-14"}]}'

run CASE-15-other-key -X POST $BASE/v1/chat/completions -H "Authorization: Bearer sk-poc-other" -H "Content-Type: application/json" \
  -d '{"model":"gpt-6-mini","messages":[{"role":"user","content":"other key CASE-15"}]}'

run CASE-16-key-in-query -X POST "$BASE/v1beta/models/mock-chat:generateContent?key=$K1" -H "Content-Type: application/json" \
  -d '{"contents":[{"role":"user","parts":[{"text":"gemini CASE-16"}]}]}'

# Must stay last: may take the host down.
run CASE-99-plugin-panic -X POST $BASE/v1/chat/completions -H "Authorization: Bearer $K1" -H "Content-Type: application/json" \
  -d '{"model":"mock-chat","messages":[{"role":"user","content":"PROBE_PANIC CASE-99"}]}'
