# Remit

Authorized, bounded and provably complete cloud activity for AI agents.

An agent working in a cloud account should be able to show, with evidence rather than assurance, that every action it took was authorized, that it could not have acted outside that authority, and that it took no action that is unaccounted for.
Tokens answer the first question and policies the second.
Tamper-evident logs prove a record has not changed, but not that it is complete: an action that was never recorded is invisible to every integrity check.
Remit's claim is all three together, with the third established against the cloud provider's own record rather than the agent's.

## How it works

1. **Warrants.** A human issues a warrant: which agent, which actions on which resources, for how long, and why. An agent can delegate part of its warrant, and a delegation can only narrow.
2. **A broker.** The agent holds no standing credentials. The broker turns a valid warrant into short-lived cloud credentials, stamped with the warrant's identifier so that the provider records it on every call.
3. **Reconciliation.** The provider's own audit record is compared with the warrants in both directions: every event must map to a warrant that permits it, and every warrant's events must be known. An action outside any warrant becomes a finding, not an absence.
4. **A witnessed log.** Warrants, credential issuance and reconciliation results go into an append-only log anchored to independent authorities, so that anyone can verify them offline without trusting the agent or the operator.

What Remit does not claim is part of the design, not a footnote: see `docs/SPEC.md` section 7 and `docs/THREAT-MODEL.md`.

## Status

Early. The specification, the threat model, the warrant semantics, signatures and delegation chains exist; the broker, the reconciler and the log do not yet.

| Part | State |
| --- | --- |
| `docs/SPEC.md`, `docs/THREAT-MODEL.md`, `docs/adr/` | Draft 0.1 |
| `remit-core`: warrants, patterns, the authorization decision, attenuation, canonical identity | Implemented, property-tested |
| Signed warrants, strict decoding, delegation chains | Implemented, property-tested (ADR 0003) |
| AWS broker | Not started |
| Reconciler | Not started |
| Witnessed log | Not started |

## Engineering

- The specification is normative. The code implements it, and where they disagree the code is wrong.
- The claims that matter are tested as properties, not examples: containment is sound (checked against brute force), and a delegated warrant never permits what its parent does not.
- Rust at a pinned toolchain, no `unsafe`, Clippy at pedantic level with warnings as errors, and as few dependencies as possible, each justified (ADR 0002).
- `bash scripts/ci.sh` runs every check; nothing merges without it passing.
- The same checks run before every commit: `git config core.hooksPath .githooks` once per clone.

## Licence

Apache-2.0. Built by [Abacross](https://abacross.com).
