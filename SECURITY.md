# Security policy

Remit's claim is about trust, so a way around it is the most important bug it can have.
That includes a way for an agent to act outside its warrant, a way for an action to escape the report, a way to rewrite the log unnoticed, and a claim in the documentation that is stronger than the code.

## Reporting

Report privately through GitHub's private vulnerability reporting (the Security tab, "Report a vulnerability"), or by email to contact-us@abacross.com with "Remit security" in the subject.
Please do not open a public issue for a vulnerability.

You will get an acknowledgement within three business days.
We will tell you whether we reproduce it, agree the disclosure date with you, and credit you in the advisory unless you ask us not to.

## What happens next

A confirmed vulnerability gets a GitHub security advisory, a fix and a release, and, where it changes what Remit claims, an entry in [the threat model's known gaps](docs/THREAT-MODEL.md#known-gaps).
Partners and customers who run Remit are told before the advisory is public, as far as the fix allows.

## Limits that are already known

The threat model lists them: [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).
A report that one of them is exploitable in a way the threat model does not describe is still welcome.

## Dependencies

Every push and every Monday, `cargo audit` checks the dependencies against the RustSec advisory database, in public (`.github/workflows/audit.yml`).
