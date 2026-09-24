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
5. The window has closed long enough for delivery. **Open:** the settling period, to be set from measurement rather than from documentation alone.

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
- `DurationSeconds` is at least 900 and at most the smaller of the role's maximum and the time left in the warrant's window. A warrant with less than 900 seconds left gets no session.
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
