# Remit specification

Status: draft 0.1, 2026-09-24.
This document is normative: the code implements it, and where they disagree the code is wrong.
Sections marked **Open** are not yet decided and must not be implemented until they are.

## 1. What Remit is for

An AI agent acting in a cloud account should be able to answer three questions with evidence rather than assurance.

1. **Authority.** Was each action it took authorized, by whom, for what purpose, within what bounds?
2. **Bounds.** Could it have taken an action outside that authority?
3. **Completeness.** Did it take any action that is not accounted for?

Existing tools answer the first question with tokens and the second with policy.
Tamper-evident logs prove that what was recorded has not changed since.
None of them proves the third: a record can be intact and still incomplete, and an action that was never recorded is invisible to every integrity check.

Remit's claim is the conjunction of all three, stated precisely in section 6 and bounded honestly in section 7.

## 2. Terms

- **Issuer.** A human, or a key held on a human's behalf, who grants authority. The root of every chain.
- **Agent.** A software principal that acts. It holds no standing cloud credentials.
- **Warrant.** A statement, signed by an issuer or by a delegating agent, of what one agent may do, where, and when.
- **Grant.** One allowance inside a warrant: a set of actions on a set of resources.
- **Request.** One concrete cloud action an agent wants to take: an action name, a resource, a time.
- **Broker.** The component that turns a valid warrant into short-lived cloud credentials, and nothing else does.
- **Cloud record.** The provider's own audit log of API calls, written by the provider, not by the agent or by Remit (on AWS, CloudTrail).
- **Reconciler.** The component that compares warrants with the cloud record, in both directions.
- **Log.** The append-only, externally anchored, witnessed record of warrants, credential issuance and reconciliation results.

## 3. Warrants

### 3.1 Fields

A warrant has exactly these fields.

| Field | Meaning |
| --- | --- |
| `version` | The encoding and semantics version. This document defines version 1. |
| `issuer` | The identifier of the key that signs the warrant. |
| `subject` | The identifier of the agent the warrant authorizes. |
| `purpose` | Free text, UTF-8, at most 512 bytes, stating why. It has no effect on authorization and is part of the record. |
| `not_before` | The first second, in UTC seconds since the Unix epoch, at which the warrant is valid. |
| `not_after` | The last second at which the warrant is valid. `not_before < not_after` is required. |
| `grants` | A non-empty list of grants. Authorization is the union of the grants. |
| `parent` | The identifier of the warrant this one was delegated from, or absent for a root warrant. |
| `max_depth` | How many further delegations this warrant permits. A root with `max_depth = 0` cannot be delegated. |

An **identifier** (for `issuer` and `subject`) is 1 to 128 characters of printable ASCII (0x21 to 0x7E).

**Limits.** A warrant has at most 64 grants, and a grant at most 64 action patterns and 64 resource patterns.
A pattern is at most 2,048 bytes, the length limit of an AWS ARN.
These bound the canonical encoding and the cost of every check; a warrant over them is refused.

There are no deny statements.
A warrant can only allow; anything not allowed is refused.
This is deliberate: it makes attenuation (section 4) decidable by a simple rule, and it removes the class of errors in which an allow and a deny interact in a way nobody predicted.

### 3.2 Grants

A grant has two fields, both non-empty lists of patterns.

- `actions`: patterns over action names, such as `s3:GetObject` or `s3:Get*`.
- `resources`: patterns over resource names, such as `arn:aws:s3:::reports-2026/*`.

A grant allows a request when some action pattern matches the request's action and some resource pattern matches the request's resource.

### 3.3 Patterns

A pattern is a non-empty string of printable ASCII (0x21 to 0x7E) in which two characters are special:

- `*` matches any sequence of characters, including the empty one;
- `?` matches exactly one character.

Every other character matches itself.
There is no escaping: a pattern cannot match a literal `*` or `?`, and neither character is valid in a resource or action name that Remit accepts.

Action matching is case-insensitive, because AWS action names are: "The prefix and the action name are case insensitive. For example, `iam:ListAccessKeys` is the same as `IAM:listaccesskeys`" (IAM policy reference, Action element).

Resource matching is case-sensitive.
AWS documents case sensitivity for some resource names ("In the `Resource` element, the IAM user name is case sensitive") but not as a rule for every service.
Where a service compares resource names without regard to case, AWS may allow a request that the warrant does not permit; section 8 states what that means for compilation, and the reconciler reports any such event as outside its warrant.

**Remit's `*` is deliberately broader than AWS's.**
In AWS resource patterns, `*` matches within one colon-separated segment of an ARN, and "If the `*` wildcard is the last character of a resource ARN segment, it can expand to match beyond the colon boundaries" (IAM policy reference, Resource element).
Remit's `*` matches any sequence, colons included.
For the same pattern text, then, everything AWS matches Remit also matches, and never the reverse.
This is the safe direction: a warrant compiled to AWS can only be enforced more narrowly than it reads, never more widely.

Implementations must reject, at construction, any warrant containing a pattern outside this alphabet, rather than normalize it.

### 3.4 The authorization decision

A warrant `W` permits a request `R = (subject, action, resource, t)` exactly when all of the following hold:

1. `R.subject = W.subject`;
2. `W.not_before <= R.t <= W.not_after`;
3. some grant in `W` allows `(R.action, R.resource)` by section 3.2.

Signature verification and chain validation (section 5) are preconditions of using a warrant at all, not part of this function; the function is pure and total.

### 3.5 Identity

A warrant's identifier is derived from its content, so the same warrant always has the same identifier and a different warrant never does, up to the collision resistance of SHA-256.

1. Encode the warrant canonically (section 3.6).
2. Take SHA-256 of the encoding.
3. Take the first 20 bytes and encode them in RFC 4648 base32, lowercase, without padding: 32 characters.
4. Prefix `rw1-`: 36 characters in total.

The result uses only `a` to `z`, `2` to `7` and `-`.
It therefore fits AWS STS SourceIdentity, which accepts 2 to 64 characters of `[\w+=,.@-]` and must not begin with `aws:`.
160 bits of the digest is far beyond any practical collision search for this use; the truncation exists only to fit the field.

### 3.6 Canonical encoding

The encoding is a byte string, written field by field in the order of section 3.1, with no optional whitespace and no alternative forms.

- Integers are unsigned, big-endian, fixed width: `version` 2 bytes, timestamps and `max_depth` 8 bytes.
- A string is its UTF-8 bytes preceded by their length as 4 bytes big-endian.
- A list is its element count as 4 bytes big-endian, then its elements.
- `parent` is one byte, `0` for absent or `1` followed by the identifier as a string.
- The encoding begins with the 8 ASCII bytes `REMITWv1`.

Grants are encoded in the order given, and patterns within a grant in the order given: two warrants that list the same grants in a different order are different warrants with different identifiers.
Implementations must not sort or deduplicate on the author's behalf, because the signature covers what the author wrote.

## 4. Delegation and attenuation

An agent may delegate part of its authority to another agent by issuing a child warrant whose `parent` is its own warrant's identifier.

A child `C` is a valid attenuation of its parent `P` exactly when:

1. `P.max_depth >= 1` and `C.max_depth <= P.max_depth - 1`;
2. `P.not_before <= C.not_before` and `C.not_after <= P.not_after`;
3. every grant in `C` is covered by some grant in `P`, where a grant `g` covers `h` when every action pattern of `h` is contained in some action pattern of `g`, and every resource pattern of `h` is contained in some resource pattern of `g`;
4. `C.issuer` is the key of `P.subject`: only the holder of a warrant can delegate from it.

Pattern `q` contains pattern `p` when every string matched by `p` is matched by `q`.

**The attenuation theorem.** If `C` is a valid attenuation of `P`, then every request `C` permits, other than in subject, is permitted by `P`.
Formally: for every `(action, resource, t)`, if `C` permits `(C.subject, action, resource, t)` then `P` permits `(P.subject, action, resource, t)`.

Implementations may decide containment conservatively: a check that sometimes answers "not contained" for patterns that are in fact contained is acceptable, because it only refuses a delegation.
A check that ever answers "contained" wrongly is a defect that breaks the theorem, and must be treated as a security vulnerability.

## 5. Signatures and chains

Decided in ADR 0003.

### 5.1 Keys and identifiers

A signing key is an Ed25519 key (RFC 8032).
Its identifier is the text `ed25519:` followed by the 32-byte public key in RFC 4648 base32, lowercase, without padding: 60 characters in all.
Every `issuer` is such an identifier.
Every `subject` that may delegate must be one too, because rule 4 of section 4 requires a child's issuer to be its parent's subject; a subject that is not a key identifier can hold a warrant but never delegate from it.

### 5.2 Signed warrants

A signed warrant is the canonical encoding of a warrant (section 3.6) together with a 64-byte Ed25519 signature over exactly those bytes by the key its `issuer` names.
The encoding begins with `REMITWv1`, which separates these signatures from any other use of the same key.

A signed warrant is valid when:

1. its bytes decode as a warrant (section 5.4);
2. its `issuer` is a key identifier;
3. the signature verifies under that key with strict verification: small-order public keys and non-canonical signature encodings are rejected.

### 5.3 Chains

A chain is a list of signed warrants `W0, W1, ..., Wn`.
It is valid for a set of trusted root keys when:

1. every `Wi` is a valid signed warrant (section 5.2);
2. `W0` has no `parent`, and its issuer is one of the trusted roots;
3. for every `i >= 1`, `Wi` is a valid attenuation of `W(i-1)` (section 4), which includes naming it as `parent` and being issued by its subject.

The authority a valid chain confers is exactly that of its last warrant, `Wn`.
By the attenuation theorem applied at every link, nothing `Wn` permits is outside what `W0` permits, other than in subject.

A chain is refused as a whole on the first rule it breaks; a verifier never uses a prefix of an invalid chain.

### 5.4 Decoding

A decoder accepts exactly the byte strings that section 3.6 produces for some valid warrant, and nothing else.
In particular it rejects trailing bytes, a wrong magic or version, a length that runs past the end, invalid UTF-8, a `parent` flag other than 0 or 1, and any content that section 3 forbids.
For every byte string a decoder accepts, encoding the result gives back the same bytes.

### 5.5 Transport

A signed warrant travels as its canonical encoding followed immediately by its 64 signature bytes.
The encoding is self-delimiting, so the signature is the last 64 bytes and everything before them must decode by section 5.4.

A chain travels as the 8 bytes `REMITCv1`, a 4-byte big-endian count of links (at most 16), and each signed warrant in order as a 4-byte big-endian length followed by its transport bytes.
Nothing may follow the last link.
Decoding a chain verifies every link's signature; checking the chain itself is section 5.3.

## 6. Completeness

This is the property that distinguishes Remit, and it is stated with its assumptions rather than without them.

Let `L` be the set of warrants in the log, and `E` the set of events in the cloud record for a set of accounts over a time window, restricted to the principals Remit manages.

**Every event is warranted.**
For every event `e` in `E`, there is a warrant `W` in `L` such that `e` carries `W`'s identifier (on AWS, as the session's SourceIdentity) and `W` permits `e`'s request.

**Every warrant is accounted for.**
For every warrant `W` in `L` whose validity window has closed, the set of events carrying `W`'s identifier is known, and each one is either permitted by `W` or reported as a violation.

A reconciliation run produces, for its window, a signed result that is either `complete` (both statements hold) or a list of specific findings: an event with no warrant, an event outside its warrant, a warrant whose events are missing from the record, or a gap in the record itself.

The claim is only as strong as its assumptions, which are part of the claim and are printed with every result:

1. The managed principals can obtain cloud credentials only through the broker. On AWS this is enforced by role trust policies that require `sts:SourceIdentity`, and it must itself be verified by the reconciler on every run, not assumed.
2. The cloud record covers the actions in question. On AWS, management events are recorded by default and data events only when configured; an action class the record does not cover is outside the claim, and the result names the classes it covered.
3. The cloud record for the window is itself complete and unaltered. On AWS, CloudTrail log file integrity validation is the evidence, and a run without it can at best report `complete, unvalidated`.
4. The action was taken by the managed session itself. AWS: "The source identity information is not captured by CloudTrail when an AWS service or service-linked role carries out an action on behalf of a federated or workforce identity" (IAM guide, monitor and control actions taken with assumed roles). Actions a service takes on a session's behalf are outside the claim, and the reconciler reports the classes it saw.
5. The window has closed long enough for delivery: the **settling period**, two hours by default, stated in every result. AWS: "CloudTrail typically delivers logs within an average of about 5 minutes of an API call. This time is not guaranteed" (CloudTrail user guide, how CloudTrail works). Measured: in the first live session, a refused call was not yet in event history about 25 minutes after it was made and was by about 85 minutes (conformance/RESULTS.md). Two hours covers that with margin; it is a parameter, not a guarantee, and an event delivered later than the settling period is outside the claim of a result already made. Re-running a window later is how a result is confirmed.

### 6.1 Inputs

A reconciliation run takes:

1. the warrants it may join to: those the log establishes at a checkpoint the reconciler's trust policy accepts, each with a chain rebuilt from logged entries that verifies against the trusted roots (sections 5.3 and 9.4); a logged warrant whose chain does not verify is not a warrant for this run and is reported;
2. the managed roles: the role ARNs the broker assumes, and each role's trust policy as observed at the time of the run;
3. the provider's events for a window `[from, to]`, from **every region** the account uses, and a statement of where they came from and what evidence of their integrity exists. CloudTrail files an event under the region that served it, not the caller's: in the first live session, a refused S3 call on a bucket in us-west-2 was recorded there, while the session's other calls were recorded in us-east-1 (conformance/RESULTS.md). A run that covered fewer regions names the ones it covered, and its verdict speaks for those regions only;
4. the time of the run.

### 6.2 Classifying events

Every event in the window is in exactly one class.

**A session creation** is an event with source `sts.amazonaws.com`, name `AssumeRole`, and a `roleArn` that is a managed role.
It must satisfy all of:

1. its `sourceIdentity` names a warrant `W` in the input;
2. its `roleSessionName` equals `W`'s identifier;
3. its `policy` is byte for byte the session policy compiled from `W` (section 8.2). AWS records the policy passed to `AssumeRole` in the event's request parameters, so a broker that passed a broader policy under a legitimate identifier is caught by the provider's own record;
4. its time is inside `W`'s window, and its `durationSeconds` does not run past `W`'s `not_after`.

A session creation that fails any of these is a **session mismatch**.

**A managed action** is any other event whose `userIdentity` is a session of a managed role.
It must carry a `sourceIdentity`, the identifier must name a warrant `W` in the input, and its time must be inside `W`'s window.
One that does not carry a known identifier is an **unwarranted event**; one outside its warrant's window is an **out-of-window event**.
A managed action with an error code is also reported as a **refused attempt**, which is information, not a failure: nothing was done.

**Everything else** is activity by principals Remit does not manage.
It is not a finding against the claim, which is about managed principals only, but it is counted by principal in every result, so that the claim's coverage is visible rather than implied.

### 6.3 The warrant cross-check

For every successful managed action, the reconciler also asks whether `W` permits the recorded action on the recorded resource (section 3.4, with the request built by section 6.5); time is not part of this question, because an event outside the window is already its own finding, and one fault is reported once.
This is a second line of defence: the primary guarantee is that AWS enforced the compiled policy, which never allows more than `W` (section 8.3).
A request the cross-check finds outside `W` is an **outside-warrant event** and fails the run, because it means either a mapping gap or a soundness failure, and both must be looked at.
A request whose resource cannot be determined is **undetermined**, reported and never guessed.

### 6.4 The verdict

A run is **complete** when it has no session mismatch, no unwarranted event, no out-of-window event and no outside-warrant event, and when every managed role's trust policy, as observed, admits only sessions with a warrant-form source identity.

The verdict is qualified, never silently upgraded:

- **complete, unvalidated** when the events came from a source without integrity evidence, such as CloudTrail event history rather than validated trail log files (assumption 3, section 6.7);
- **provisional** when `to` is later than the time of the run minus the settling period (assumption 5).

Any failure makes the verdict **incomplete**, with every finding listed.

### 6.5 From an event to a request

- **Action:** the event source without `.amazonaws.com`, a colon, and the event name. Where a service's IAM action differs from its event name, the difference is a mapping gap, surfaced by the cross-check rather than hidden by it. **Open:** a per-service table of such differences.
- **Resource:** every ARN in the event's `resources`. An event with none is undetermined.
- **Subject:** the warrant's subject; **time:** the event time.

### 6.6 The result

A result is a JSON document written once and signed as written: the signature is over the exact bytes, and a verifier checks it before parsing.
It states the window, the event source and its integrity evidence, the settling period, the regions covered, the inputs refused, the managed roles and whether each trust policy was as required, the verdict, every finding with its event identifier, the per-warrant event counts, and the unmanaged activity by principal.
The reconciler signs with its own key, which is not a warrant issuer's key.

The signature is Ed25519 over the 8 bytes `REMITRv1` followed by the result's exact bytes.
The prefix separates the two things Remit signs: a warrant's signed bytes begin with `REMITWv1` (section 3.6), so a signature over a result can never be presented as a signature over a warrant, or the reverse, and a signer refuses to sign in the warrant domain through the result interface.
The signature travels beside the result as a JSON file, `<result>.sig`: `{"domain": "REMITRv1", "key": <the signer's key identifier, section 5.1>, "signature": <64 bytes, lowercase hex>}`.
A verifier is given the key it expects, refuses any other domain or key, and checks the signature with the strict rules of section 5.2 before parsing the result.

### 6.7 A validated record

A run may take its events from the trail's log files instead of event history, and then, and only then, its verdict may be **complete**.
With log file integrity validation on, CloudTrail delivers a digest file every hour in every region, even an hour with no activity, listing the SHA-256 of the uncompressed content of each log file delivered in that hour, and chained to the previous digest by its location, the SHA-256 of its uncompressed content, and its RSA signature (CloudTrail user guide, "CloudTrail digest file structure" and "Custom implementations of CloudTrail log file integrity validation").

For each region the run covers, the reconciler requires a chain of digests that:

1. were read from the bucket and key they record;
2. each verify with SHA-256 and RSA (PKCS #1 v1.5) under the CloudTrail public key their fingerprint names, over the end time, `bucket/key`, the hex SHA-256 of the digest's uncompressed bytes and the previous digest's signature, each on its own line; the newest digest's signature is read from its object's `x-amz-meta-signature`, and every older one's from its successor;
3. link without a break: each names the previous one's location, hash and signature, and starts where the previous one ends, so there is no hour without a digest;
4. are not restarted inside the window: a starting digest, with no previous digest, means validation was turned off and on again;
5. cover the window from its start to its end plus the settling period, measured in delivery time, which is what digests record; and
6. list log files that are all present and whose SHA-256 matches.

Every failure is a **record gap** finding and fails the run.
The events are then the records of the verified log files whose event time falls in the window.
**Unverified:** that the hash of the digest's own content in item 2 is over its uncompressed bytes. AWS states this for the previous digest's hash and for log files but not in so many words for the current digest; the fact that settles it is one real digest verifying.

## 7. What Remit does not claim

- It does not judge intent. A warranted action can still be the wrong one; the warrant says who allowed it.
- It does not cover principals it does not manage. A human with their own credentials is outside the claim, and the reconciler reports what it does not cover rather than implying it covers everything.
- It does not make the cloud record trustworthy; it states which evidence of the record's integrity it relied on.
- It does not prevent an action the cloud permits and the warrant permits. It makes that action attributable.

## 8. AWS mapping

Decided in ADR 0006.
The constraints below are AWS facts, quoted from its references; the choices are marked as such.

### 8.1 Sessions

A warrant is used on AWS through an STS session obtained by the broker with `AssumeRole`:

- `SourceIdentity` is the warrant identifier (section 3.5). AWS: SourceIdentity is 2 to 64 characters of `[\w+=,.@-]`, and "persists across chained role sessions" (STS API reference, AssumeRole).
- `Policy` is the session policy compiled from the warrant (section 8.2). AWS: "The resulting session's permissions are the intersection of the role's identity-based policy and the session policies."
- `DurationSeconds` is at least 900 and at most the smaller of the role's maximum and the time left in the warrant's window less a 60-second margin for request latency and clock skew. A warrant with less than 900 seconds left after the margin gets no session. The margin exists because the first live session, planned to end exactly at `not_after` by this machine's clock, ended one second later by AWS's; the reconciler found it (section 6.2).
- The role's trust policy allows `sts:AssumeRole` only to the broker's principal, and requires `sts:SourceIdentity` to be present (choice), so no session on that role exists without a warrant identifier stamped on it.

### 8.2 Compiling a warrant to a session policy

The compiled policy has `"Version": "2012-10-17"` and one `Allow` statement per grant, with the grant's action patterns as `Action` and its resource patterns as `Resource`, copied byte for byte, and a condition limiting it to the warrant's window:

`"Condition": {"DateGreaterThanEquals": {"aws:CurrentTime": <not_before>}, "DateLessThanEquals": {"aws:CurrentTime": <not_after>}}`

with both times in ISO 8601 UTC (`YYYY-MM-DDTHH:MM:SSZ`).
It is serialized without whitespace, in the order of the warrant's grants, so one warrant has one compiled policy.

The compiler **refuses**, rather than approximates, a warrant with:

1. a pattern containing `${`. AWS substitutes policy variables in `Resource` when the version is `2012-10-17` ("Variables were introduced in version `2012-10-17`"; IAM reference, policy variables), so `${...}` would match something other than what the warrant says;
2. an action pattern that is not `*` and not a service prefix without wildcards, a colon, and a name;
3. a resource pattern that is not `*` and not an ARN with at least five colons and no wildcard in its service segment ("You can't use a wildcard in the service segment"; IAM reference, Resource element);
4. a compiled policy over 2,048 characters ("The plaintext that you use for both inline and managed session policies can't exceed 2,048 characters"; STS API reference). A shorter policy that allowed less would be a different warrant; a refusal tells the issuer to split the work.

### 8.3 Compilation soundness

**The compiled policy never allows a request the warrant does not permit.**

The argument has three parts, and each is either a fact quoted above or a property the tests check.

1. The compiler copies every pattern verbatim and adds nothing to what a statement allows except the window condition, which only narrows. Property-tested: parsing the compiled policy gives back exactly the warrant's grants and window.
2. For the same pattern text, AWS matches a subset of what Remit matches: action matching is case-insensitive in both, and AWS's `*` is confined to an ARN segment except at a segment's end, where Remit's `*` is not confined at all (section 3.3). With `${` refused, AWS has nothing to substitute.
3. The session's permissions are the intersection of this policy and the role's, so they are no larger than this policy.

The one assumption that is not a documented fact is resource case: AWS does not state that every service compares resource names with regard to case (section 3.3).
Until a per-service table exists, the reconciler is the backstop: an event whose resource differs only in case from what the warrant permits is reported as outside it.

**Conformance.** Beyond the argument, compiled policies are checked against AWS's own evaluator, the IAM policy simulator, on generated warrants and requests: every request the simulator allows must be one the warrant permits.
The first run, on 2026-09-24, found no violation in 144 decisions across five services, and the simulator treated resource case as significant in every probe; `conformance/RESULTS.md` has the detail and its limits.

## 9. The log

Decided in ADR 0007.
The tree is RFC 9162's with SHA-256, and checkpoints, notes, cosignatures, the witness protocol and the served layout are C2SP's (tlog-checkpoint, signed-note, tlog-cosignature, tlog-witness, tlog-tiles).
This section defines only what Remit adds: what goes in, who must have signed, and when an entry must be there.

### 9.1 Entries

An entry is the 8 bytes `REMITLv1`, one kind byte, and a body:

- kind `0x01`, **a warrant**: the body is one signed warrant in its transport form (section 5.5). Every link of a chain is its own entry.
- kind `0x02`, **a result**: the body is the SHA-256 of a reconciliation result's exact bytes (32 bytes), the reconciler's Ed25519 public key (32 bytes), and the result's signature (64 bytes, section 6.6). The result itself is published beside the log under its hash; the entry fixes which result was signed, by which key, and in what order.

An entry is at most 65,535 bytes, the most a tile's entry bundle can carry (tlog-tiles prefixes each entry with a 16-bit length).
A signed warrant whose transport form is longer than 65,526 bytes therefore cannot be logged, and by section 9.3 cannot be used.
A warrant small enough to compile to an AWS session policy (at most 2,048 characters, section 8.2) is far below this.

The log appends only entries whose signatures verify: a warrant entry by section 5.2, a result entry against the result's bytes, which the appender supplies.
An entry's leaf hash is `SHA-256(0x00 || entry)` (RFC 9162 section 2.1.1).

### 9.2 Checkpoints and witnesses

A checkpoint is the log's origin, size and root, as a signed note (tlog-checkpoint).

1. The log signs with an Ed25519 note key (signature type `0x01`) whose key name is the log's origin.
2. A checkpoint has no extension lines. The checkpoint specification calls them not auditable; Remit refuses them.
3. A witness cosigns with a timestamped Ed25519 key (signature type `0x04`, tlog-cosignature), and only after the checks of tlog-witness: the checkpoint is signed by a log key it trusts for the origin; its old size is the size of the last checkpoint it cosigned for that origin; the consistency proof from that checkpoint verifies (section 2.1.4 of RFC 9162); a checkpoint of the same size has the same root; a checkpoint of size zero has the empty tree's root.
Witnesses are reached over HTTP with tlog-witness's `add-checkpoint` call; `remit witness serve` is a witness any party can run, and it answers each refusal with the status that specification assigns.

4. A verifier holds a **trust policy**: the log's key, the witness keys it trusts, and a quorum `k`. A checkpoint is trusted when its note verifies, it is signed by the log key for the log's own origin, and at least `k` distinct witness public keys cosigned it. A signature line from a key the verifier knows that fails to verify rejects the whole note; lines from unknown keys are ignored.

Base64 in notes, keys and checkpoints has one accepted spelling (RFC 4648 section 4, padded, with zero unused bits), so a signed object cannot be re-encoded without breaking its signature.

### 9.3 Logged before used

The broker issues a session for a chain only when every link is **proven logged**: for each link, the broker holds a checkpoint that its trust policy accepts, the link's entry index, and an inclusion proof of the entry's leaf hash in that checkpoint's tree (RFC 9162 section 2.1.3), and the proof verifies.
The proof travels as text: the line `remit-logged/v1`; then one line per link, in chain order, holding the entry index in decimal and the inclusion proof's hashes in base64, separated by single spaces; then a blank line; then the checkpoint as a signed note with its cosignatures.
The trust policy is text too: `log <vkey>`, one `witness <vkey>` line per trusted witness, and `quorum <k>`, where each vkey is in the signed-note verifier key form; a quorum larger than the number of distinct witness keys is refused, since no checkpoint could meet it.

It follows that every warrant ever honoured is in the log, where anyone who reads the log can see it.
An issuer key used without its holder's knowledge leaves entries the holder can find, which is what threat model assumption 3 relies on.

No freshness is required of the proving checkpoint.
A witness cosigns only checkpoints consistent with every one it cosigned before, so an entry proven in one trusted checkpoint is in every later checkpoint the same witnesses cosign, and cannot be removed from the history a verifier trusts without the log and a quorum of that verifier's witnesses acting together.

### 9.4 The log and reconciliation

The set `L` of section 6 is the set of warrants whose entries are included in a checkpoint the reconciler's trust policy accepts.
A result names that checkpoint (origin, size and root), and an event carrying an identifier that is not in `L` is an unwarranted event, whatever else the reconciler may have been shown.
Every signed result is appended to the log as a result entry, with its bytes published beside it (section 9.5).

### 9.5 Serving

The log is served as tlog-tiles static files: `checkpoint`, `tile/<L>/<N>` and `tile/entries/<N>`, each with the paths and partial-tile rules of that specification.
Results are served beside them at `result/<hex SHA-256>`.
Tiles and results never change once written; only `checkpoint` does.
Files whose names begin with a dot (the writer's lock, files being written) belong to the writer and are never served.

### 9.6 What the log does not claim

- It does not stop a thief with an issuer key from logging and using a warrant. It makes that warrant public, and the reconciler reports every event under it.
- It does not choose witnesses for the verifier. A verifier that trusts witnesses the log's operator controls has no split-view defence.
- It is on the broker's path: when inclusion cannot be proven, no session is issued. Remit fails closed, so the log's availability is part of Remit's.

## 10. Approvers

Decided in ADR 0008.
An approver is an agent that decides, per request, whether another agent may take one action without a person, and records the decision as a warrant.
Its judgement may come from rules or from a model; this section fixes what any approver must do regardless of how it judges, so that no judgement can grant more than a human already bounded.

### 10.1 The bound

A human issues the approver a warrant `B` whose subject is the approver's key and whose `max_depth` is at least 1.
Everything the approver issues is a child of `B` (section 4), so by the attenuation theorem it permits nothing `B` does not.

### 10.2 A request

A request names the agent (the child's subject), one action, one resource, a duration, the agent's purpose, and optional context.
Action and resource are concrete names, not patterns: they contain no `*` or `?`.
The context is untrusted: it is shown to the decider and never parsed for instructions by the approver.

### 10.3 The decision, in order

1. **Form.** A request that is not well formed, or whose action or resource is a pattern, is refused.
2. **Bound.** The child is built (10.4) and checked as an attenuation of `B`; if it is not one, the request is refused. No decider is asked.
3. **Rules.** A request whose action matches one of the approver's hard-rule action patterns (section 3.3) is escalated. No decider is asked.
4. **Decider.** The decider returns a risk band, one of `read_only`, `reversible_change`, `sensitive_or_external` and `destructive`, and a probability that the action is safe to take without a person. An error, a timeout or an answer outside these forms escalates.
5. **Threshold.** The child is issued only when the band is one the approver's configuration allows and the probability is at or above its threshold; otherwise the request is escalated.

**Refused** means the request can never be approved under `B`; **escalated** means a person must decide.
Every decision, whatever its outcome, is recorded by the approver with the input hash of 10.5.

### 10.4 The child

The child's issuer is the approver's key and its subject the requesting agent; it has one grant, the requested action on the requested resource; its window starts at the time of the decision (or `B`'s `not_before`, if later) and ends after the requested duration (or at `B`'s `not_after`, if sooner); its `max_depth` is 0; its parent is `B`.
Its purpose is the evidence line of 10.5, followed by ` | ` and the agent's purpose, cut at a character boundary to fit 512 bytes.

### 10.5 Evidence

The evidence line is `remit-approval/v1` followed by space-separated `key=value` fields: `decider` (the decider's name), `model` (the model the decider reports), `band`, `p` (the probability, four decimals), `threshold`, and `input`.
`input` is `sha256:` and the first 16 bytes, in lowercase hex, of the SHA-256 of the state shown to the decider: a JSON object with the keys `action`, `context`, `purpose` and `resource`, in that order, without whitespace.
Because the approver signs the child and the child is logged before use (section 9.3), the evidence is public and cannot be altered after the fact.

### 10.6 Bands from AWS's service reference

An approver may take the band from AWS's service reference information, the machine-readable metadata AWS publishes for every IAM action, instead of from a model.
Each action carries four flags, `IsList`, `IsWrite`, `IsPermissionManagement` and `IsTaggingOnly`, and all four false means the action only reads (AWS, Service Authorization Reference, "Simplified AWS service information for programmatic access").
The band is `sensitive_or_external` when `IsPermissionManagement` is set; otherwise `destructive` for a write whose name begins with `Delete`, `Terminate`, `Destroy`, `Purge`, `Remove` or `Revoke`; otherwise `reversible_change` for any other write or a tagging-only action; otherwise `read_only`.
AWS does not say which writes cannot be undone, so the `destructive` split is this specification's judgement from the verb; it changes only the reason given, since by default every band but `read_only` goes to a person.
An action the loaded reference does not list is escalated.

Taken this way, the band cannot be moved by anything the agent writes.
Two things it cannot tell, and which the approver must handle elsewhere: whether a particular resource is sensitive (reading one object is a read, whatever the object holds), which is the bound's job or an optional model's; and reads AWS does not flag at all though they disclose secrets, such as `secretsmanager:GetSecretValue` and `ssm:GetParameter`, which the default hard rules send to a person.
When a model is also configured, its band is ignored and its probability decides only whether a read is safe without a person.
