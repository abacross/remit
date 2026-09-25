#!/usr/bin/env bash
# publish-log.sh - publish a Remit log's served files to a GitHub Pages repository.
#
#   bash scripts/publish-log.sh <log-dir> <policy-file> <checkout-dir>
#
# Copies exactly what c2sp.org/tlog-tiles serves (`checkpoint`, `tile/...`) and the trust
# policy into a clone of the Pages repository, commits and pushes. Never the writer's
# dotfiles (SPEC 9.5), and never `result/`: Abacross's reconciliation reports name its AWS
# account, which it does not publish, so only their signed commitments are in the log.
set -euo pipefail
[ $# -eq 3 ] || { sed -n '2,10p' "$0"; exit 2; }
LOG=$1 POLICY=$2 OUT=$3
[ -f "$LOG/checkpoint" ] || { echo "no checkpoint in $LOG" >&2; exit 1; }
[ -d "$OUT/.git" ] || { echo "$OUT is not a clone of the Pages repository" >&2; exit 1; }
unset $(git -C "$OUT" rev-parse --local-env-vars)
rm -rf "$OUT/tile"
cp "$LOG/checkpoint" "$OUT/checkpoint"
[ -d "$LOG/tile" ] && cp -R "$LOG/tile" "$OUT/tile"
cp "$POLICY" "$OUT/policy.txt"
touch "$OUT/.nojekyll"   # serve tile paths as they are
# Nothing private may leave: no 12-digit account numbers anywhere in what is published.
if grep -rIEl '(^|[^0-9])[0-9]{12}([^0-9]|$)' "$OUT/checkpoint" "$OUT/policy.txt" 2>/dev/null; then
  echo "refusing: an account-number-like string in the published files" >&2; exit 1
fi
SIZE=$(sed -n 2p "$OUT/checkpoint")
git -C "$OUT" add -A
if git -C "$OUT" diff --cached --quiet; then echo "  nothing new to publish"; exit 0; fi
git -C "$OUT" commit -q -m "checkpoint at size $SIZE"
git -C "$OUT" push -q origin main
echo "  published checkpoint at size $SIZE"
