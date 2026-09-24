#!/usr/bin/env python3
"""
iam-simulator.py - check compiled session policies against AWS's own evaluator.

    cargo run -q -p remit-aws --example conformance_cases > cases.jsonl
    python3 conformance/iam-simulator.py cases.jsonl

For every case it asks the IAM policy simulator (iam:SimulateCustomPolicy, read-only and
free) whether the compiled policy allows the request at the given time, and compares:

  * AWS allows and Remit does not permit: a SOUNDNESS VIOLATION (SPEC section 8.3). Exit 1.
  * Remit permits and AWS denies: expected where AWS matches more narrowly; counted.

Needs credentials that may call iam:SimulateCustomPolicy. Touches no resource.
"""
import json
import sys
import time

import boto3


def main(path):
    iam = boto3.client("iam")
    cases = [json.loads(l) for l in open(path) if l.strip()]
    tally = {"agree_allow": 0, "agree_deny": 0, "aws_narrower": 0, "violation": 0, "aws_rejects_input": 0}
    for c in cases:
        for attempt in range(5):
            try:
                r = iam.simulate_custom_policy(
                    PolicyInputList=[c["policy"]],
                    ActionNames=[c["action"]],
                    ResourceArns=[c["resource"]],
                    ContextEntries=[{"ContextKeyName": "aws:CurrentTime",
                                     "ContextKeyValues": [c["time"]], "ContextKeyType": "date"}],
                )
                break
            except iam.exceptions.InvalidInputException as e:
                # A probe AWS does not accept as a request at all (for example an ARN
                # whose "arn:aws" prefix was uppercased): not a decision, so not a finding.
                r = None
                print(f"  input rejected by AWS: {c['resource']}  ({str(e).split(': ', 1)[-1][:80]})")
                break
            except iam.exceptions.ClientError as e:
                if "Throttling" in str(e) and attempt < 4:
                    time.sleep(2 ** attempt)
                    continue
                raise
        if r is None:
            tally["aws_rejects_input"] += 1
            continue
        aws = r["EvaluationResults"][0]["EvalDecision"] == "allowed"
        remit = c["remit_permits"]
        if aws and remit:
            tally["agree_allow"] += 1
        elif not aws and not remit:
            tally["agree_deny"] += 1
        elif remit and not aws:
            tally["aws_narrower"] += 1
            print(f"  narrower  {c['window']:6} {c['action']:28} {c['resource']}")
        else:
            tally["violation"] += 1
            print(f"  VIOLATION {c['window']:6} {c['action']:28} {c['resource']}  (AWS allows, Remit does not)")
        time.sleep(0.1)
    print(json.dumps(tally))
    return 1 if tally["violation"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
