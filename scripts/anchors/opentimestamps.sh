#!/bin/sh
# opentimestamps.sh - a `remit log anchor` submitter for OpenTimestamps (free, keyless,
# committed to Bitcoin).
#
#   remit log anchor --dir <log> --submit scripts/anchors/opentimestamps.sh
#
# Given a checkpoint digest (SHA-256, hex) as $1, writes the proof under
# $REMIT_ANCHORS/proofs/ and prints a JSON receipt naming it. The client adds a random
# nonce before submitting, so the calendar servers learn nothing, not even the digest.
# Adapted from agent-journal's submitter.
#
# A fresh proof is a PENDING commitment, not yet evidence: it becomes one when the Bitcoin
# transaction confirms, hours later, and `ots upgrade` is run on it. An un-upgraded proof
# looks exactly like a real one, so upgrade on a schedule.
#
# Requires the OpenTimestamps client (`pip install opentimestamps-client`).
set -eu

DIGEST="$1"
DIR="${REMIT_ANCHORS:?remit log anchor sets this}/proofs"
mkdir -p "$DIR"

command -v ots >/dev/null 2>&1 || {
  echo "the ots client is not installed" >&2
  exit 1
}

# ots stamps a file, so the digest goes in a file of its own; its bytes are the hex text.
printf '%s' "$DIGEST" > "$DIR/$DIGEST.digest"
ots stamp "$DIR/$DIGEST.digest" >/dev/null 2>"$DIR/$DIGEST.err" || {
  cat "$DIR/$DIGEST.err" >&2
  rm -f "$DIR/$DIGEST.err" "$DIR/$DIGEST.digest"
  exit 1
}
rm -f "$DIR/$DIGEST.err"

[ -f "$DIR/$DIGEST.digest.ots" ] || {
  echo "no proof was produced" >&2
  exit 1
}

printf '{"kind":"opentimestamps","proof":"proofs/%s.digest.ots","state":"pending","note":"run ots upgrade after the bitcoin transaction confirms"}\n' \
  "$DIGEST"
