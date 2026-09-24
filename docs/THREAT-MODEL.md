# Threat model

Status: draft 0.1, 2026-09-24.
Read with `SPEC.md`; section numbers below refer to it.

## Assets

- **Authority**: the issuer keys, and the warrants they sign.
- **Cloud access**: the roles the broker can assume, and the sessions it creates.
- **The record**: the log of warrants, issuance and reconciliation results, and the cloud provider's own audit record that Remit reconciles against.
- **The claim**: a `complete` result is the product. A false `complete` is the worst failure Remit can have, worse than an outage, because people act on it.

## Adversaries

Each is considered alone and in combination with the others.

| # | Adversary | Can | Remit's position |
| --- | --- | --- | --- |
| A1 | A misbehaving agent (bug, bad instruction, prompt injection) | Take any action its credentials allow; write anything to its own logs | The central case. Bounded by the session policy; every action attributable by SourceIdentity; the agent's own logs are never evidence. |
| A2 | A compromised agent host | Everything A1 can, plus read the agent's keys and live session credentials | Credentials are short-lived and warrant-scoped; a delegation key can only narrow its own authority (section 4). Theft is bounded by the warrant, not by the role. |
| A3 | A delegating agent that over-delegates | Sign child warrants | A child that exceeds its parent fails attenuation and is refused (section 4). |
| A4 | An operator of Remit itself | Run the broker and the log | The log is anchored to external authorities and witnessed, so the operator cannot rewrite it unnoticed. The operator can refuse service, which is visible, but cannot forge a `complete` over events it hid, because the cloud record is the provider's, not the operator's. |
| A5 | A human with their own cloud credentials | Act outside Remit entirely | Out of scope for bounds, in scope for honesty: such principals are not managed, and every result says which principals it covers. |
| A6 | A cloud administrator | Change roles, trust policies, trails | The reconciler verifies, on every run, the configuration its assumptions depend on (section 6, assumptions 1 and 3). A changed trust policy or a stopped trail turns `complete` into a finding. |
| A7 | A network attacker | Observe and tamper with traffic | TLS to the provider and to the log; warrants are signed, so tampering is detected, not trusted. |

## Assumptions

Remit's guarantees depend on these, and each result restates the ones it relied on.

1. The cryptographic primitives hold: SHA-256 collision resistance, and the signature scheme (ADR 0003).
2. The cloud provider enforces its own policies as documented, and its audit record is written by the provider.
3. Issuer keys are held by the humans they name. Key custody is the issuer's responsibility; Remit makes a stolen issuer key visible in the log, not impossible to use.
4. Clocks are within 60 seconds of AWS's. The broker keeps that margin between a session's end and its warrant's end (SPEC section 8.1), and the reconciler checks every session against AWS's recorded time, so a larger skew shows up as a session mismatch rather than going unseen.

## Out of scope

- The correctness of an action that was authorized. Remit records who allowed it.
- Side channels on the agent host.
- The provider's internal integrity beyond what it documents and signs.
- Denial of service against the broker or the log, beyond failing closed: without the broker, an agent gets no credentials.

## Failure principles

- **Fail closed.** A warrant that cannot be verified, compiled within limits, or chained is refused. Nothing is granted by default.
- **Never round up.** A limit that cannot be expressed exactly (a session policy over 2,048 characters, a pattern outside the alphabet) is a refusal, never an approximation, because an approximation is a different grant.
- **Say what was not checked.** A result that relied on an assumption it could not verify says so in the result, not in a footnote.
