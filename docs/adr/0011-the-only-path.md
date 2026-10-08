# 0011: The only path: make "the agent has no other key" something Remit checks

Date: 2026-10-08. Status: accepted for design by the owner on 2026-10-08 (Abacross decision 60 and the discussion that followed); built in the order below.

## Context

Remit's claims hold only when the broker is the agent's only way to act in the account.
Today that is a deployment assumption, stated in `docs/PRODUCTION.md` and nowhere checked.
The owner's review of 2026-10-07 and 2026-10-08 found what follows from it:

- If the agent can reach a second AWS credential (the person's profile, an instance role, a key in a file), it does not need to get around Remit; it can simply not use it.
- The reconciler sees that activity in CloudTrail, but lists it as unmanaged activity by principal, and the run can still say `complete`.
  An agent using a person's key is reported as that person, and nothing is flagged.
- Uninstalling `remit mcp` is not itself a bypass: with no second credential the agent can then do nothing.
  The bypass is always the second credential.

So "the only path" has to be a state Remit can check, before a session and after it, not a promise in a guide.

## Decision

**The target state.** Every principal that can act in a governed account is in one of four categories:

1. **Agents**, through the broker, on managed roles whose trust policy admits only the broker (already checked by every reconciliation, SPEC 6.4).
2. **People**, through federated sign-in with a phishing-resistant second factor that software cannot complete.
3. **Pipelines**, through roles that trust one OIDC subject (a repository and branch), with no stored key.
4. **Service roles**, assumable only by an AWS service principal.

A principal in none of them is a finding.
Break-glass is a person in category 2 on a named role, and its use is always a finding to review, never an error.

**Three checks make it verifiable, built in this order.**

1. **`remit inventory`** classifies every principal that can act in an account into the four categories, from read-only IAM and Identity Center calls: IAM users with active access keys, every role by the principals its trust policy admits, permission sets, and resource policies that grant to a principal outside the account.
   Its output is a signed list the reconciler takes as an input, so the classification is reviewed by a person once and then held fixed until it changes.
2. **The preflight.** `remit mcp` and `remit run` refuse to start when the agent's user can reach an AWS credential other than the broker's: `AWS_*` credential variables, shared credentials and config files (including `credential_process` and SSO caches), a web identity token file, the container credentials endpoint, and the instance metadata service.
   The result is written to the journal at every start.
   On a machine the agent controls the preflight is advice, since the agent could change it; in the production layout the binary is root-owned and the preflight holds.
   The reconciler, not the preflight, is the authority.
3. **The reachable-identity finding.** The reconciler takes the inventory and a list of identities agents could reach, and reports two new findings that make a run `incomplete`:
   - `outside-remit`: activity by an identity on the agent-reachable list that no warrant covers;
   - `unclassified-principal`: activity by a principal the inventory does not place in a category.

**Then, to make the state reachable without breaking a customer's production:**

4. **Warrant proposals from observed activity.** In shadow mode, before any key is removed, the reconciler records what each agent's current identity does; `remit propose` turns a window of that activity into draft warrants per kind of work, for a person to edit and sign.
5. **A service control policy pack** under `deploy/aws/scp/`: deny creating IAM users and access keys except to a break-glass role, deny changes to managed roles' trust policies except by the deployment pipeline, and deny stopping or narrowing the trail.
6. **A multi-account `setup.sh`**, for an AWS organization: managed roles and the reconciler's role in each member account, one broker service, an organization trail.

## What stays open

- Whether a human session was signed in with a phishing-resistant factor is not reliably visible in CloudTrail for every sign-in path; until it is, category 2 is checked by `remit inventory` from Identity Center's settings, not per session.
  To settle: confirm which CloudTrail fields carry the authentication method for Identity Center role sessions.
- Activity off the cloud is out of scope, as before (decision 60).

## Consequences

- "The agent has no other key" becomes a finding when false, which the site, the films and the onboarding work can rely on.
- Reconciliation takes one more input, the signed inventory; a run without one says so and cannot report the two new findings.
- The inventory's IAM and Identity Center reads are free; IAM Access Analyzer's external-access analyzer is free, and its unused-access analyzer is charged, so the inventory does not use it.
- The checks, the policy pack and the setup script are open source under ADR 0005, because a customer needs them to verify the claim.
  How Abacross runs an engagement to reach this state is not, and lives with Abacross.
