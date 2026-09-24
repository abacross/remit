# Conformance results

Each run checks compiled session policies against AWS's own evaluator, the IAM policy simulator (`iam:SimulateCustomPolicy`), on the cases emitted by `cargo run -p remit-aws --example conformance_cases`.
A **violation** is a request AWS allows and the warrant does not permit (SPEC section 8.3); any violation fails the run.

## 2026-09-24

160 cases: 8 warrants over S3, DynamoDB, SQS, Lambda and IAM; for each, ten requests (exact, case-flipped, segment-crossing, other account, other action, other bucket) at a time inside and a time after the window.

| Outcome | Count |
| --- | --- |
| AWS allows, Remit permits | 42 |
| AWS denies, Remit denies | 101 |
| Remit permits, AWS denies (AWS narrower) | 1 |
| **AWS allows, Remit does not (violation)** | **0** |
| Input AWS rejects as not an ARN | 16 |

The one narrower case is the one SPEC section 3.3 predicts: in `arn:aws:dynamodb:us-east-1:*:table/orders`, AWS's `*` stays within the account segment, so an account value containing `/` and `:` does not match; Remit's `*` does. That is the safe direction.

Every request whose resource differed from the warrant's only in the case of its resource part was denied by the simulator, as Remit denies it.
This is evidence for the one soundness assumption SPEC section 8.3 names (resource case), for these five services and in the simulator; it is not a guarantee for every service or for live enforcement, and the reconciler remains the backstop.

The 16 rejected inputs are ARNs uppercased from `arn:aws:` onward, which AWS does not accept as requests at all.
