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

## First reconciliation, 2026-09-24

`remit reconcile` over 19:30Z to 21:03:08Z, us-east-1 and us-west-2, event history: 384 events.

- **Verdict: incomplete**, correctly. The three sessions of the first live runs were each found to outlive their warrant by about a second, the defect the broker's 60-second margin now prevents; each is a session mismatch.
- The refused `GetBucketVersioning` was a refused attempt (found in us-west-2); `GetCallerIdentity` was undetermined (its event names no resource); the trust policy held; 3 sessions and 3 managed actions joined to the one warrant.
- Unmanaged activity was counted by principal: 62 events by the account's administrator user, which is the credential this machine's agent still runs on, and the rest by AWS services and service roles. That is the coverage limit of dogfooding on this machine, measured rather than asserted.
- The report was signed by a reconciler key in the `REMITRv1` domain; `remit verify-report` accepted it, rejected a copy whose verdict was edited to "complete", and rejected a check against another key.

## The whole loop, live, 2026-09-24 (decision 39)

One warrant through every part: issued by a throwaway test root, logged, used, reconciled against the provider's record, and the result logged.

- **Logged before used.** A local log (`abacross.com/remit/dev-log`) with one witness and a policy requiring its cosignature. The warrant (`rw1-tqryfmhfrvq66qwswp7ctte2cndobmln`, `s3:GetBucketLocation` on one bucket, 20 minutes) was appended and proven. A second warrant, identical but never logged, was refused by `remit run` before any AWS call ("link 0 of the chain is not proven logged").
- **Used.** `remit run` issued a 1,129-second session (the warrant's remaining time less the 60-second margin) as `assumed-role/remit-agent-readonly/rw1-tqryfmhf...`; `GetBucketLocation` succeeded.
- **Reconciled** after the two-hour settling period, over the warrant's window (21:40:27Z to 22:00:27Z) in us-east-1 and us-west-2, joining only to warrants the log established at its trusted checkpoint: 27 events, **verdict `complete-unvalidated`**, the expected verdict for event history, which carries no integrity evidence. One session and two managed actions joined to the warrant; the trust policy held; no input refused. The one finding is information: `GetCallerIdentity` names no resource and is undetermined. Unmanaged activity in the window, by principal: AWS services 18, the administrator user 2 (the broker's own credential), and two service roles 2 each.
- **Result logged.** The signed report verified, and was appended to the log as entry 1 (checkpoint size 2, cosigned). A copy with the verdict edited to `complete` failed `remit verify-report` and was refused by the log. The warrant's proof made at size 1 still verified at size 2: no freshness is needed (SPEC 9.3).
