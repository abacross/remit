#!/bin/sh
# rfc3161.sh - a `remit log anchor` submitter for an RFC 3161 timestamp authority.
#
#   remit log anchor --dir <log> --submit scripts/anchors/rfc3161.sh
#
# Given a checkpoint digest (SHA-256, hex) as $1, writes the authority's token under
# $REMIT_ANCHORS/tokens/ and prints a JSON receipt naming it. Keyless: nothing but the
# digest leaves the machine. Adapted from agent-journal's submitter, which anchors
# Abacross's operations journal the same way.
#
# openssl and curl speak the protocol rather than hand-written ASN.1, because home-made
# DER is the kind of bug that verifies happily and proves nothing.
set -eu

DIGEST="$1"
TSA="${TSA_URL:-https://freetsa.org/tsr}"
DIR="${REMIT_ANCHORS:?remit log anchor sets this}/tokens"
mkdir -p "$DIR"

REQ="$DIR/$DIGEST.tsq"
RES="$DIR/$DIGEST.tsr"

# -cert asks the authority to include its certificate chain in the response: without it,
# a token becomes unverifiable the day that authority disappears.
openssl ts -query -digest "$DIGEST" -sha256 -cert -out "$REQ" >/dev/null 2>&1

curl -sS --max-time 30 -H "Content-Type: application/timestamp-query" \
     --data-binary "@$REQ" "$TSA" -o "$RES"

# An authority that is down often answers HTML with a 200, so check the shape, not the
# exit code.
openssl ts -reply -in "$RES" -text >/dev/null 2>&1 || {
  rm -f "$RES"
  echo "the authority did not return a parseable timestamp token" >&2
  exit 1
}

GENTIME=$(openssl ts -reply -in "$RES" -text 2>/dev/null | sed -n 's/^Time stamp: //p')

# The path is relative to anchors/, so the log stays movable and publishable.
printf '{"kind":"rfc3161","tsa":"%s","token":"tokens/%s.tsr","tsa_time":"%s"}\n' \
  "$TSA" "$DIGEST" "${GENTIME:-unknown}"
