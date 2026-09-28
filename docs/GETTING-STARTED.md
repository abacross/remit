# Getting started

Remit lets an AI agent act in your cloud account only under a warrant a person signed, and shows afterwards, from the cloud's own record, that it did nothing else.
This guide takes you from nothing to an agent working under a warrant, then to a daily routine.
AWS only today.

There are three parts:

1. [See it work in five minutes](#1-see-it-work-in-five-minutes-no-aws), with no AWS account.
2. [Set up your project](#2-set-up-your-project), about thirty minutes, most of it the one-time AWS setup.
3. [Day to day](#3-day-to-day), how warrants fit into your development workflow.

A last section says [what must be true before you trust a `complete`](#before-you-trust-a-complete).

## 1. See it work in five minutes, no AWS

You need Rust 1.98 or newer, `git` and `jq`.

```sh
git clone https://github.com/abacross/remit && cd remit
cargo build -p remit-cli
bash examples/mcp/demo.sh
```

The demo makes real keys, a real signed warrant and a real witnessed log in a temporary directory, then talks to `remit mcp` exactly as an agent framework would.
You will see the agent's three tools, a permitted and a refused action with the reason, a program the server was not allowed to start, and a warrant that was never logged being refused before anything could reach AWS.

## 2. Set up your project

### Install

Download the binary for your platform from the [latest release](https://github.com/abacross/remit/releases/latest): static Linux builds for x86_64 and arm64, and macOS on Apple silicon.
Each comes with a SHA-256 sum and a signed build provenance attestation, which proves it was built by this repository's release workflow from the tagged commit:

```sh
gh attestation verify remit-<version>-<target>.tar.gz --repo abacross/remit
tar xzf remit-<version>-<target>.tar.gz
```

Put `remit` from the unpacked directory on your `PATH`.
Or build it yourself with Rust:

```sh
cargo install --locked --git https://github.com/abacross/remit remit-cli
```

### Initialise

In your project's directory:

```sh
remit init
```

It makes, in `.remit/`, the agent's key, a log with a local witness and the trust policy that names them, and a copy of the AWS role template.
It makes your issuing key at `~/.config/remit/root.key` (or uses the one already there), outside the project.
It prints the four next steps with the exact values for your machine; they are the steps below.
Nothing in `.remit/` is overwritten by a second `remit init`, and `.remit/.gitignore` keeps the keys out of git.

### Keep the agent away from your issuing key

Whoever can read `root.key` can sign warrants, so the agent must not be able to.
`remit init` prints the Claude Code permission rule to add to `~/.claude/settings.json`.
That rule stops Claude Code's own file tools and commands such as `cat`, but not a script that opens the file itself; for that, enable Claude Code's sandbox, or keep the issuing key on another machine and run `remit task` there.

### Give the broker an identity, once

The broker turns a warrant into short-lived credentials.
It needs an AWS identity that can do one thing: assume Remit's role with a warrant id as the session's source identity.
An IAM user or role with this policy, and nothing else, is enough:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["sts:AssumeRole", "sts:SetSourceIdentity"],
    "Resource": "arn:aws:iam::<account>:role/remit-agent-readonly",
    "Condition": {"StringLike": {"sts:SourceIdentity": "rw1-*"}}
  }]
}
```

`remit mcp` uses whatever AWS credentials are in its environment as the broker's.
Keep them out of the agent's reach if you can: see [known gap 3](THREAT-MODEL.md#known-gaps) for what happens when the agent can read them too.

### Deploy the role, once per account

Run the command `remit init` printed, with the broker's ARN:

```sh
aws cloudformation deploy --stack-name remit-agent-readonly \
  --template-file .remit/role.yaml --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides BrokerPrincipalArn=arn:aws:iam::<account>:user/remit-broker
```

The role's policy is the ceiling: by default `ReadOnlyAccess`, so no warrant on this role can ever allow a write.
For work that changes things, deploy a second stack with another `RoleName` and a `CeilingPolicyArn` that allows those writes; every warrant still narrows it.

### Sign the first warrant

```sh
remit task --grant 's3:ListBucket=arn:aws:s3:::my-bucket' --for 1h \
  --purpose "find last week's exports"
```

`remit task` issues the warrant with your issuing key, appends it to the log, has the witness cosign, proves it logged, and makes it the agent's current warrant (`.remit/current.chain` and `.remit/current.proof`).
A grant is `ACTIONS=RESOURCES`, each a comma-separated list of patterns where `*` matches anything; repeat `--grant` for more.
`--for` takes seconds, or a number with `s`, `m`, `h` or `d`.

### Connect the agent

With Claude Code, load the plugin and give it the values `remit init` printed:

```sh
claude --plugin-dir /path/to/remit/integrations/claude-plugin
```

The plugin gives the agent three tools (`remit_warrant`, `remit_check`, `remit_run`), a skill for working inside a warrant, and a hook that refuses direct `aws`, `az` and `gcloud` commands so that the agent uses `remit_run`.
Any other MCP client can run the server directly:

```json
{"mcpServers": {"remit": {"command": "remit", "args": [
  "mcp", "--chain", "/abs/path/.remit/current.chain", "--root", "ed25519:...",
  "--role", "arn:aws:iam::<account>:role/remit-agent-readonly",
  "--log-policy", "/abs/path/.remit/log.policy",
  "--log-proof", "/abs/path/.remit/current.proof", "--allow", "aws"]}}}
```

The server reads the current warrant on every call, so the next `remit task` takes effect on the agent's next call with no restart.

### Check what happened

CloudTrail delivers events within minutes but does not guarantee it, so reconcile a window at least two hours after it closes.
Reconciling makes read-only calls to CloudTrail and IAM with whatever credentials are in its environment, and signs its report with its own key, not your issuing key:

```sh
remit key new --out ~/.config/remit/reconciler.key
remit reconcile --log-dir .remit/log --log-policy .remit/log.policy \
  --root <your issuing key id> --role arn:aws:iam::<account>:role/remit-agent-readonly \
  --region us-east-1 --from 2026-09-28T00:00:00Z --to 2026-09-29T00:00:00Z \
  --key ~/.config/remit/reconciler.key --out report.json
```

The verdict is `complete` only when every session and every action on the managed roles maps to a logged warrant and stays inside it, the role's trust policy is as required, and the record itself is validated; otherwise it is `incomplete` and lists each finding with its event id.
The report counts what each warrant was used for, by action, and counts everything done by identities Remit does not manage, by identity.
Reconciling reads CloudTrail event history, so its verdict says `complete, unvalidated`; SPEC section 6.7 shows how to reconcile from the trail's validated log files instead.

## 3. Day to day

- **One warrant per task.** Put the ticket or pull request in `--purpose`; the warrant and its purpose are in the log for good.
- **Short windows.** A warrant cannot be revoked before it ends ([known gap 2](THREAT-MODEL.md#known-gaps)), so give each the time the task needs, not the week.
- **Ceilings by role.** A read-only role for exploring, a narrower write role per kind of change; the warrant narrows further. Production gets its own roles and narrower warrants than development.
- **Warrants in review.** `remit warrant show --chain .remit/current.chain` prints the warrant in plain text for a pull request, so a reviewer sees what the agent was allowed as well as what it wrote.
- **Keep the record.** Commit `.remit/log/` and `.remit/warrants/` (never the keys) so the history of what agents were allowed travels with the code.
- **Reconcile on a schedule.** Run `remit reconcile` daily over the previous day, fail the job on `incomplete`, and append each signed report to the log with `remit log append-result`.
- **Agents in CI.** A pipeline job runs `remit mcp` under a warrant issued for that run, with the broker's credentials held by the pipeline, not by the agent's steps.

## Before you trust a `complete`

A `complete` verdict is exactly as strong as these, and the report restates the ones it relied on:

- **The record covers the actions.** CloudTrail records management events by default and data events, such as reading an S3 object, only where you turn them on; turn them on for the resources that matter.
- **The record is validated.** A trail with log file validation, reconciled from its files (SPEC 6.7), across every region you use.
- **Only the broker can make managed sessions.** The role's trust policy admits only the broker (the reconciler checks this on every run), and the broker's credentials are out of the agent's reach.
- **Only people sign warrants.** The issuing key is out of the agent's reach.
- **The log has independent witnesses.** The local witness `remit init` sets up shows the mechanism and protects against nothing its operator might do; add witnesses the verifier trusts (`remit log append --witness-url`).
- **Nobody else is quietly acting.** Identities Remit does not manage are counted in every report, not judged; an administrator with standing access is outside the claim.

The full list of assumptions and known gaps is in [THREAT-MODEL.md](THREAT-MODEL.md).
