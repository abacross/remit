#!/usr/bin/env bash
# fetch-trail.sh - copy what `remit reconcile --trail-dir` needs from a CloudTrail bucket.
#
#   bash scripts/fetch-trail.sh <bucket> <account> <yyyy/mm/dd> <out-dir> <region>...
#
# TRAIL_BUCKET_REGION names the bucket's region (default us-east-1).
#
# Copies, for each region and that day, the digest files and log files (only those two
# prefixes), the CloudTrail public keys valid that day, and the S3-metadata signature of
# the newest digest per region. Read-only, but S3 GET, LIST and HEAD requests are billed
# per request (a day is a few hundred objects per region: fractions of a cent), so run it
# only when a validated reconciliation is wanted.
set -euo pipefail
[ $# -ge 5 ] || { sed -n '2,11p' "$0"; exit 2; }
BUCKET=$1 ACCOUNT=$2 DAY=$3 OUT=$4
shift 4
mkdir -p "$OUT/copy"
for REGION in "$@"; do
  for KIND in CloudTrail-Digest CloudTrail; do
    PREFIX="AWSLogs/$ACCOUNT/$KIND/$REGION/$DAY/"
    aws s3 sync --only-show-errors "s3://$BUCKET/$PREFIX" "$OUT/copy/$PREFIX"
  done
done
# Each region signs its digests with its own key, fetched from that region (AWS: "you
# must retrieve its public key from the same Region"); merged into one list.
START="${DAY//\//-}T00:00:00Z"
for REGION in "$@"; do
  aws cloudtrail list-public-keys --region "$REGION" --start-time "$START" --output json > "$OUT/keys-$REGION.json"
done
python3 - "$OUT" "$@" <<'PY'
import json, os, sys
out, regions = sys.argv[1], sys.argv[2:]
merged, seen = [], set()
for r in regions:
    for k in json.load(open(os.path.join(out, f"keys-{r}.json")))["PublicKeyList"]:
        if k["Fingerprint"] not in seen:
            seen.add(k["Fingerprint"])
            merged.append(k)
json.dump({"PublicKeyList": merged}, open(os.path.join(out, "keys.json"), "w"), indent=1)
PY
# The newest digest per region: its signature is only in S3 metadata.
python3 - "$OUT" "$BUCKET" "$ACCOUNT" "$DAY" "$@" <<'PY'
import json, os, subprocess, sys
out, bucket, account, day, regions = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5:]
sigs = {}
for region in regions:
    prefix = f"AWSLogs/{account}/CloudTrail-Digest/{region}/{day}/"
    local = os.path.join(out, "copy", prefix)
    names = sorted(os.listdir(local)) if os.path.isdir(local) else []
    if not names:
        continue
    key = prefix + names[-1]
    head = json.loads(subprocess.check_output(["aws", "s3api", "head-object", "--region", os.environ.get("TRAIL_BUCKET_REGION", "us-east-1"), "--bucket", bucket, "--key", key, "--output", "json"]))
    sigs[key] = head["Metadata"]["signature"]
json.dump(sigs, open(os.path.join(out, "signatures.json"), "w"), indent=1)
print(f"  {len(sigs)} newest-digest signatures")
PY
echo "  copied to $OUT; reconcile with: --trail-dir $OUT/copy --trail-bucket $BUCKET --trail-keys $OUT/keys.json --trail-signatures $OUT/signatures.json"
