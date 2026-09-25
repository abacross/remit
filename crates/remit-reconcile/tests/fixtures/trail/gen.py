#!/usr/bin/env python3
"""
gen.py - CloudTrail digest chains for the trail validator's tests, signed as AWS signs them.

Builds, for two regions, four hourly digests in the format of AWS's "CloudTrail digest
file structure" (the first a starting digest), log files they list, and the signatures,
using a throwaway 2048-bit RSA key made here and discarded: only its public key (PKCS #1
DER, as ListPublicKeys returns it) is written. Python's `cryptography` signs, so the Rust
verifier is checked against an independent implementation.

  python3 gen.py > trail.json
"""
import base64, hashlib, json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

BUCKET = "example-trail-bucket"
ACCOUNT = "111122223333"
TRAIL = "example-trail"
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
FINGERPRINT = hashlib.md5(der).hexdigest()


def hour(h):
    return f"2026-09-24T{h:02d}:01:31Z"


def stamp(h):
    return f"20260924T{h:02d}0131Z"


def sign(data):
    return key.sign(data.encode(), padding.PKCS1v15(), hashes.SHA256()).hex()


out = {"key": {"fingerprint": FINGERPRINT, "der_b64": base64.b64encode(der).decode()}, "digests": [], "logs": []}
for region in ("us-east-1", "us-west-2"):
    prev = None
    for i, h in enumerate(range(10, 14)):
        logs = []
        if i != 2:  # the third hour had no activity: an empty digest, as AWS delivers
            events = [{
                "eventVersion": "1.10", "eventID": f"{region}-{h}-{n}", "eventTime": f"2026-09-24T{h:02d}:{10 + n:02d}:00Z",
                "eventSource": "s3.amazonaws.com", "eventName": "ListBuckets", "awsRegion": region,
                "userIdentity": {"type": "IAMUser", "arn": f"arn:aws:iam::{ACCOUNT}:user/admin"},
                "requestParameters": None, "resources": [],
            } for n in range(2)]
            obj = f"AWSLogs/{ACCOUNT}/CloudTrail/{region}/2026/09/24/{ACCOUNT}_CloudTrail_{region}_{stamp(h)[:-3]}_{h}.json.gz"
            text = json.dumps({"Records": events})
            out["logs"].append({"bucket": BUCKET, "object": obj, "text": text})
            logs.append({"s3Bucket": BUCKET, "s3Object": obj, "hashValue": hashlib.sha256(text.encode()).hexdigest(),
                         "hashAlgorithm": "SHA-256", "newestEventTime": events[-1]["eventTime"], "oldestEventTime": events[0]["eventTime"]})
        obj = f"AWSLogs/{ACCOUNT}/CloudTrail-Digest/{region}/2026/09/24/{ACCOUNT}_CloudTrail-Digest_{region}_{TRAIL}_us-west-2_{stamp(h + 1)}.json.gz"
        digest = {
            "awsAccountId": ACCOUNT, "digestStartTime": hour(h), "digestEndTime": hour(h + 1),
            "digestS3Bucket": BUCKET, "digestS3Object": obj,
            "digestPublicKeyFingerprint": FINGERPRINT, "digestSignatureAlgorithm": "SHA256withRSA",
            "newestEventTime": None, "oldestEventTime": None,
            "previousDigestS3Bucket": prev and BUCKET, "previousDigestS3Object": prev and prev["object"],
            "previousDigestHashValue": prev and prev["sha256"], "previousDigestHashAlgorithm": prev and "SHA-256",
            "previousDigestSignature": prev and prev["signature"],
            "logFiles": logs,
        }
        text = json.dumps(digest)
        sha = hashlib.sha256(text.encode()).hexdigest()
        signature = sign(f"{hour(h + 1)}\n{BUCKET}/{obj}\n{sha}\n{prev['signature'] if prev else 'null'}")
        out["digests"].append({"bucket": BUCKET, "object": obj, "text": text, "signature": signature})
        prev = {"object": obj, "sha256": sha, "signature": signature}
print(json.dumps(out, indent=1))
