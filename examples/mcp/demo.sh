#!/usr/bin/env bash
# demo.sh - `remit mcp` end to end, without touching AWS (ADR 0009).
#
#   bash examples/mcp/demo.sh [path/to/remit]
#
# Makes real keys, a real signed warrant, a real log with a witness cosignature and a
# real inclusion proof in a temporary directory, then speaks the Model Context Protocol
# to `remit mcp` over stdio exactly as an agent framework would, and checks every reply:
#
#   - the handshake, and exactly three tools;
#   - remit_warrant describes the warrant, proven logged;
#   - remit_check permits what the warrant grants and refuses what it does not, with why;
#   - remit_run refuses a program the server was not allowed to start;
#   - a second warrant that was never logged is refused by remit_check and remit_run
#     before anything could reach AWS (SPEC 9.3);
#   - remit_run with a logged warrant reaches the broker, which finds no AWS credentials
#     here (the server is started with none, on purpose) and reports an error, not a crash.
#
# The role ARN uses AWS's documentation placeholder account; nothing here calls AWS.
set -euo pipefail
REMIT="${1:-$(cd "$(dirname "$0")/../.." && pwd)/target/debug/remit}"
[ -x "$REMIT" ] || { echo "no remit binary at $REMIT; cargo build -p remit-cli first" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail() { echo "  FAIL: $*" >&2; exit 1; }
ok() { echo "  ok    $*"; }

ORIGIN=example.test/remit-mcp-demo WNAME=example.test/witness
for k in root agent log witness; do "$REMIT" key new --out "$T/$k.key" >/dev/null; done
ROOT=$("$REMIT" key id --key "$T/root.key"); AGENT=$("$REMIT" key id --key "$T/agent.key")
"$REMIT" warrant issue --key "$T/root.key" --subject "$AGENT" --valid-for 3600 --purpose "remit mcp demo" \
  --grant 's3:GetObject,s3:ListBucket=arn:aws:s3:::demo-bucket,arn:aws:s3:::demo-bucket/*' --out "$T/chain" >/dev/null
"$REMIT" warrant issue --key "$T/root.key" --subject "$AGENT" --valid-for 3600 --purpose "never logged" \
  --grant 's3:GetObject=arn:aws:s3:::demo-bucket/*' --out "$T/unlogged" >/dev/null
"$REMIT" log create --dir "$T/log" --key "$T/log.key" --origin "$ORIGIN" >/dev/null
"$REMIT" log append --dir "$T/log" --key "$T/log.key" --origin "$ORIGIN" --chain "$T/chain" \
  --witness-key "$T/witness.key" --witness-name "$WNAME" --witness-state "$T/witness.state" >/dev/null
{ echo "log $("$REMIT" log vkey --key "$T/log.key" --name "$ORIGIN" --kind log)"
  echo "witness $("$REMIT" log vkey --key "$T/witness.key" --name "$WNAME" --kind witness)"
  echo "quorum 1"; } > "$T/policy"
"$REMIT" log prove --dir "$T/log" --policy "$T/policy" --chain "$T/chain" --out "$T/proof" >/dev/null
# The unlogged warrant gets the logged one's proof, which does not cover it.
cp "$T/proof" "$T/unlogged.proof"

session() { # $1 chain, $2 proof, then JSON lines on stdin; replies on stdout
  env -i PATH="$PATH" HOME="$T" AWS_SHARED_CREDENTIALS_FILE=/dev/null AWS_CONFIG_FILE=/dev/null \
    AWS_EC2_METADATA_DISABLED=true AWS_REGION=us-east-1 \
    "$REMIT" mcp --chain "$1" --root "$ROOT" --role arn:aws:iam::111122223333:role/demo \
      --log-policy "$T/policy" --log-proof "$2" --allow aws --timeout-seconds 20
}
call() { printf '{"jsonrpc":"2.0","id":%s,"method":"tools/call","params":{"name":"%s","arguments":%s}}\n' "$1" "$2" "$3"; }

echo "remit mcp, one session under a logged warrant"
OUT=$( { printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"0"}}}' \
                      '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
                      '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
         call 3 remit_warrant '{}'
         call 4 remit_check '{"action":"s3:GetObject","resource":"arn:aws:s3:::demo-bucket/report.csv"}'
         call 5 remit_check '{"action":"s3:DeleteObject","resource":"arn:aws:s3:::demo-bucket/report.csv"}'
         call 6 remit_run '{"argv":["sh","-c","env"]}'
         call 7 remit_run '{"argv":["aws","s3","ls","s3://demo-bucket"]}'; } | session "$T/chain" "$T/proof")
r() { jq -c "select(.id==$1)" <<<"$OUT"; }
[ "$(r 1 | jq -r .result.protocolVersion)" = 2025-06-18 ] && ok "handshake, protocol 2025-06-18" || fail "initialize: $(r 1)"
[ "$(jq -c 'select(.id==null)' <<<"$OUT")" = "" ] && ok "the initialized notification got no reply" || fail "a notification was answered"
[ "$(r 2 | jq -c '[.result.tools[].name]')" = '["remit_warrant","remit_check","remit_run"]' ] && ok "exactly three tools" || fail "tools: $(r 2)"
W=$(r 3 | jq .result.structuredContent)
[ "$(jq -r .subject <<<"$W")" = "$AGENT" ] && [ "$(jq -r .logged.proven <<<"$W")" = true ] \
  && ok "remit_warrant: $(jq -r .warrant_id <<<"$W"), $(jq -c .grants[0].actions <<<"$W"), logged in $(jq -r .logged.at <<<"$W")" || fail "remit_warrant: $(r 3)"
[ "$(r 4 | jq -r .result.structuredContent.permitted)" = true ] && ok "remit_check permits s3:GetObject" || fail "check permit: $(r 4)"
[ "$(r 5 | jq -r .result.structuredContent.permitted)" = false ] && ok "remit_check refuses s3:DeleteObject: $(r 5 | jq -r .result.structuredContent.reason)" || fail "check deny: $(r 5)"
[[ "$(r 6 | jq -r '.result.content[0].text')" == "refused: sh is not one of the programs"* ]] && ok "remit_run refuses sh: $(r 6 | jq -r '.result.content[0].text')" || fail "allow list: $(r 6)"
[ "$(r 7 | jq -r .result.isError)" = true ] && ok "remit_run under a logged warrant reached the broker, which found no AWS credentials here: $(r 7 | jq -r '.result.content[0].text' | head -c 120)" || fail "run without credentials: $(r 7)"

echo "remit mcp, a warrant that was never logged"
OUT=$( { call 8 remit_check '{"action":"s3:GetObject","resource":"arn:aws:s3:::demo-bucket/report.csv"}'
         call 9 remit_run '{"argv":["aws","s3","ls","s3://demo-bucket"]}'; } | session "$T/unlogged" "$T/unlogged.proof")
[ "$(r 8 | jq -r .result.structuredContent.permitted)" = false ] && ok "remit_check: $(r 8 | jq -r .result.structuredContent.reason | head -c 110)" || fail "unlogged check: $(r 8)"
T9=$(r 9 | jq -r '.result.content[0].text')
[[ "$(r 9 | jq -r .result.isError)" = true && "$T9" == refused:* ]] && ok "remit_run refused before AWS: $(head -c 110 <<<"$T9")" || fail "unlogged run: $(r 9)"
echo "all checks passed"
