# Lessons

Recorded technique, by kind of work.
Read the section before doing that kind of work; add an entry in the same commit when a fix takes more than two attempts, a check disproves a belief, or a technique proves reusable.

## AWS behaviour, verified

- A CloudTrail event name is the API operation, not the IAM action that authorizes it. AWS publishes the mapping for every service as the service reference (`https://servicereference.us-east-1.amazonaws.com/`, `Operations[].AuthorizedActions`); `scripts/gen-authorizing-actions.py` turns it into the reconciler's table.
- Some event sources are not the IAM prefix: CloudWatch records as `monitoring.amazonaws.com` (seen in a real record, 2026-09-28).
- A service calling in a session's name (a forward access session) is recorded with the session's identity and source identity, a different access key, the service's host name as `sourceIPAddress`, and no `invokedBy` (CodeCommit decrypting with KMS, 2026-09-28).
- CloudTrail records `policyArns` in an `AssumeRole` event's request parameters (tested 2026-09-29).
- The Rust SDK honours `AWS_ENDPOINT_URL`, `AWS_ENDPOINT_URL_<SERVICE>` and a profile's `endpoint_url`; `refuse_endpoint_overrides` makes the SDK's own per-service lookup to refuse them.
- S3 data events' resource lists are unverified: no documented example was found (2026-09-28).

## Testing

- A Lambda binary can be tested end to end on a laptop: serve the Runtime API (`GET /2018-06-01/runtime/invocation/next` with the request-id headers, `POST .../response`) and start the binary with `AWS_LAMBDA_RUNTIME_API` pointing at it.
- Mutation-test every security check: remove it, and the test that covers it must fail.
- Run new reconciler rules over a real day's record before release; fixtures do not show what AWS actually writes.

## HTTP servers

- Read the request body before sending any reply, including a refusal. A reply sent with the body unread closes the connection with data waiting in it, the kernel answers with a TCP reset, and the client may see "connection reset" instead of the status. It showed as a test that failed about one workspace run in two and never alone (`remit-witness`, 2026-09-29); the fix reads and discards up to a cap.
- To reproduce a failure that only appears under load, rerun the whole workspace's tests in a loop and keep each run's log, rather than rerunning the one test alone.

## Lints (pedantic clippy, warnings are errors)

- `too_many_lines`: extract functions along the natural seams rather than allowing the lint.
- `struct_excessive_bools`: allow it, with the reason, only where the struct mirrors someone else's settings.
- `type_complexity` in tests: name the type with a `type` alias.
- Closures in test tables must end their statements with `;` (`semicolon_if_nothing_returned`).

## Disk

- Cargo never deletes old build outputs, and with full debug information each copy of a program was about 370 MB; `target/` reached 36 GB (2026-09-30). `[profile.dev] debug = "line-tables-only"` made the `remit` debug binary 109 MB and a full CI build 3.4 GB; run `cargo clean` when it creeps back.

## Releases

- The release pipeline attests `dist/*.tar.gz` and `dist/*.zip`; verify a release as a user would (`gh release download`, `sha256sum -c SHA256SUMS`, `gh attestation verify`) before installing it.
- Security fixes stay on a local branch until the owner approves the advisory; then fast-forward `main`, tag, verify, publish the advisory, and mark older releases.
