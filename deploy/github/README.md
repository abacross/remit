# Reconciling where the agents cannot reach

A reconciler judges the agents, so it must not run where they do.
On an agent's machine, the agent's user can replace the binary, edit the trusted roots and the log policy it reads, and use its key (THREAT-MODEL, known gaps 10 and 11).
`reconcile.yml` runs it in GitHub Actions instead, from a repository no agent's identity can write.

## Set it up

1. Create a private repository, and give no agent's GitHub identity write access to it.
   If an agent works with a person's own GitHub credentials, this boundary does not hold: give the agent an identity of its own first.
2. Deploy `deploy/aws/reconciler-role.yaml` with that repository's OIDC subject prefix (`gh api repos/<owner/name>/actions/oidc/customization/sub --jq .sub_claim_prefix`; `deploy/aws/setup.sh reconciler <owner/name>` looks it up).
   The role reads CloudTrail and the managed roles' trust policies, and nothing else; GitHub's OIDC token is how the workflow assumes it, so no AWS key exists.
3. In the repository, commit the trust anchors:
   - `trust/roots.txt`: the issuers' root key identifiers, one per line;
   - `trust/log.policy`: the log's trust policy file (log key, witnesses, quorum).
4. Set repository variables:
   - `REMIT_VERSION`: the release to run, such as `v0.1.4`;
   - `REMIT_LOG_REPOSITORY`: the clone URL of the repository that serves the log;
   - `REMIT_AWS_ROLE`: the role's ARN from step 2;
   - `REMIT_ROLES`: the managed roles' ARNs, separated by spaces;
   - `REMIT_BROKERS`: the broker principals' ARNs, separated by spaces (the broker service's `BrokerRoleArn`);
   - `REMIT_REGIONS`: every region the agents' sessions are created or used in, separated by spaces.
5. Make the reconciler's key with `remit key new --out reconciler.key` on a machine no agent uses, store its contents as the secret `REMIT_RECONCILER_KEY`, and delete the file.
   Publish the key's identifier (`remit key id`) where verifiers can find it: `remit verify-report --key-id` checks results against it.
6. Copy `reconcile.yml` to `.github/workflows/`.

Each day at 06:00 UTC it reconciles the previous day, four hours after that window's settling period, commits the signed result to `reports/`, and fails if the verdict is incomplete, so the failure reaches whoever watches the repository.
