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

## Live session, 2026-09-24

The first session through `remit run`, on role `remit-agent-readonly` (deploy/aws/role.yaml, ceiling ReadOnlyAccess), with a warrant signed by a throwaway test root key allowing exactly `s3:GetBucketLocation` on one bucket.

- The role refused `AssumeRole` with no source identity ("not authorized to perform: sts:AssumeRole") and with a source identity not of the warrant form ("not authorized to perform: sts:SetSourceIdentity"), both from the account's administrator user.
- Through `remit run`: `GetBucketLocation` succeeded; `GetBucketVersioning`, which the role's ceiling allows, was refused by AWS "because no session policy allows the s3:GetBucketVersioning action"; the session's principal was `assumed-role/remit-agent-readonly/rw1-w27scolum43jyvkjja4g4tb7rgsgnal7`.
- CloudTrail event history (us-east-1) recorded `GetBucketLocation` with `userIdentity.sessionContext.sourceIdentity` equal to the warrant identifier, and the three `AssumeRole` events with the same `sourceIdentity`, within about a minute of the calls.
- The refused `GetBucketVersioning` **was** recorded, with `errorCode` `AccessDenied` and the same `sourceIdentity`, but in **us-west-2**, the bucket's region, not in us-east-1 where the successful call was logged, and later: it was not in event history about 25 minutes after the call, and was by about 85 minutes. Two consequences, now in SPEC 6.1: a run must cover every region the account uses, or say which it covered; and the settling period must allow for a delay longer than the few minutes the successful call took.
- The reconciler's first run over these events found that the session outlived its warrant by one second (planned from this machine's clock, logged a second later by AWS's); the broker now keeps a 60-second margin.
