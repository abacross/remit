# Threat model

Status: 0.2, 2026-09-28. Supersedes draft 0.1 of 2026-09-24.
Read with `SPEC.md`; section numbers below refer to it.

This version is a STRIDE review of every component, checked against an independent red-team review of release 0.1.3 made the same day, which tried each threat against the code and reproduced what it could.
Where the review found a way around a claim, the fix is named below with the test that now fails without it.
What is not fixed is marked **Open** and says why.

## What Remit claims

Remit makes three claims, and this document asks of each threat which claim it attacks.

1. **Authorized.** Every session on a managed role was opened under a warrant that chains to a trusted root key and was logged before use.
2. **Bounded.** A session can do no more than its warrant grants, because the cloud provider enforces the policy compiled from it.
3. **Complete.** A reconciliation that says `complete` has joined every managed action in the provider's record to a warrant that permits it, and would have said `incomplete` otherwise.

A false `complete` is the worst failure Remit can have, worse than an outage, because people act on it.

## How to read the tables

| Status | Meaning |
| --- | --- |
| **Prevented** | The attack fails. The evidence is a test, a proof or the provider's documented enforcement. |
| **Detected** | The attack can succeed, and the reconciler or a verifier reports it; the verdict becomes `incomplete` or the verification fails. |
| **Accepted** | The attack is possible, is outside what Remit claims, and every result says so. |
| **Open** | The attack is possible and weakens a claim. It is listed in the known gaps with its fix. |

## Trust boundaries

Each box drawn around a group is a trust boundary; arrows are the data flow, numbered in order; `[n]` is the component's section below.
The two items marked **gap** are where the default setup puts something on the agent's side of a boundary.

```mermaid
flowchart TB
  subgraph P["Person with the issuing key"]
    W["Signs a warrant [1][2]"]
    AP["Model approver, only inside a person's bound [3]"]
  end
  subgraph L["Public log, run by other parties"]
    LOG["Log: checkpoints, warrants, results [4]"]
    WIT["Witnesses cosign"]
    ANC["Anchors: timestamp authority, Bitcoin"]
  end
  subgraph H["Agent's machine, the agent's user"]
    AG["Agent"]
    RUN["remit run / remit mcp, hook as a guide rail [6]"]
    ST[".remit/ state [10]"]
    BK["Broker key: gap 3"]
    IK["Issuing key file: gap 6"]
  end
  subgraph A["AWS account"]
    STS["STS: trust policy admits the broker only [5]"]
    SES["Session on a managed role, policy = the warrant"]
    SVC["AWS services"]
    CT["CloudTrail [7]"]
  end
  subgraph R["Reconciler and verifiers"]
    REC["remit reconcile [7]"]
    RES["Signed result, verify-report [8]"]
  end
  subgraph B["Releases"]
    REL["Release build: sums, provenance, SBOM [9]"]
  end
  W -- "1 warrant appended" --> LOG
  AP --> LOG
  LOG --> WIT
  LOG --> ANC
  LOG -- "2 proof it is logged" --> RUN
  AG --> RUN
  BK -.-> RUN
  RUN -- "3 AssumeRole: warrant id, session policy" --> STS
  STS -- "4 session" --> SES
  SES -- "5 calls" --> SVC
  SES --> CT
  SVC --> CT
  CT -- "6 events" --> REC
  LOG -- "7 logged warrants" --> REC
  REC -- "8 signed result, appended to the log" --> RES
  REL -. "installs remit" .-> RUN
```

The boundaries that matter are between the agent and three things it must not hold: the issuing key, the broker's credentials, and the log's and witnesses' keys.
Most of what is Open below is a place where the default setup puts one of them on the agent's side.
A zone is a trust boundary only when a different principal holds it: another operating-system user, another machine, another organization, or AWS itself.
The section "Boundaries, crossing by crossing" checks each arrow above for that, and for what the receiving side checks.

## Assets

- **Authority:** the issuing keys and the warrants they sign.
- **Cloud access:** the roles the broker can assume and the sessions it opens.
- **The record:** the log of warrants, records and results; its anchors; and the provider's own audit record.
- **The claim:** a result, and what its verdict is qualified by.

## Adversaries

Each is considered alone and together with the others.

| # | Adversary | Can |
| --- | --- | --- |
| A1 | A misbehaving agent (a bug, a bad instruction, prompt injection) | Take any action its credentials allow; write anything to its own files and logs |
| A2 | A compromised agent host | All of A1, and read every file and process environment of the agent's user |
| A3 | A delegating agent that over-delegates | Sign child warrants |
| A4 | An operator of Remit itself | Run the broker, the log and the reconciler |
| A5 | A person with their own cloud credentials | Act outside Remit entirely |
| A6 | A cloud administrator | Change roles, trust policies, resource policies and trails |
| A7 | A network attacker | Observe and alter traffic |
| A8 | A compromised dependency or build tool | Run code in the build, or in Remit itself |
| A9 | A person with an issuing key who acts in bad faith, or whoever stole it | Sign any warrant |
| A10 | Someone who wants a result to say more than it does | Choose the reconciler's inputs, or present a result out of context |
| A11 | Colluding witnesses | Cosign what the log operator asks |

## STRIDE by component

### 1. Issuing keys and signatures

| | Threat | Status | Evidence |
| --- | --- | --- | --- |
| S | A warrant signed without the issuing key | Prevented | Ed25519 with strict verification (SPEC 5.2); `signatures.rs`: a forged issuer fails, any altered byte is rejected. |
| S | A warrant signed by a key the verifier does not trust | Prevented | A chain must start at a trusted root; demonstrated on 2026-09-28 with an impostor key ("root issuer ... is not trusted"). |
| T | A warrant's bytes altered after signing | Prevented | Canonical encoding: the decoder re-encodes and compares, so only one byte string decodes to a warrant (`a_mutated_encoding_is_refused_or_is_exactly_canonical`). |
| T | A signature over one kind of document presented as another | Prevented | Domain separation: `REMITWv1` for warrants, `REMITRv1` for results, and the result signer refuses the warrant domain (`domain_signatures_do_not_cross_domains_or_impersonate_warrants`). |
| R | An issuer denies having issued a warrant | Detected | The broker honours only warrants proven logged, and the log is witnessed (section 9.3). |
| I | The issuing key is read by the agent | Prevented in the production layout; **Open** in the single-machine one | `remit init` keeps the key in `~/.config/remit/root.key`, under the agent's own user when the agent runs as the person; the permission rules it prints do not stop a script (known gap 6). |
| E | A stolen or misused issuing key mints a broad warrant | Detected, partly | The warrant is public in the log before the broker honours it, so a person reviewing the log sees it; but the log does not prove that it was logged before its session was opened (known gap 7). |

### 2. Warrants, patterns and delegation

| | Threat | Status | Evidence |
| --- | --- | --- | --- |
| E | A child warrant grants more than its parent | Prevented | `check_attenuation` on every link of every chain; property tests of the attenuation theorem; the red team's exhaustive check of 115,600 pattern pairs found no false containment. |
| E | AWS reads a pattern more broadly than Remit does | Prevented | The compiler refuses whatever AWS would read differently, and policy variables (`everything_aws_would_read_differently_is_refused`). |
| E | A grant lets work escape the warrant: `iam:PassRole`, `sts:AssumeRole`, credentials or IAM changes that outlive it, resource policy changes, code that runs later, reads that return credentials (ECR tokens, database tokens, Secrets Manager values) | Prevented at issuance, unless allowed | New: `remit warrant issue` and `remit task` name each such grant and refuse without `--allow-escape` (`a_grant_that_escapes_the_warrant_needs_saying_so`). The list is the known ways out, not a proof there are no others; the role's own permissions remain the ceiling. |
| S | A warrant used by an agent other than its subject | Prevented with the broker service (new); **Open** where `remit run` holds the broker's key | A warrant is a bearer credential: nothing binds the caller to the warrant's `subject`, and every warrant is public in the log, so anyone who can reach a broker can use any valid one, and the result names the wrong subject (known gap 5). |
| D | A long window that cannot be cut short | Accepted | No revocation (known gap 2). |

### 3. Model approvers (ADR 0008)

| | Threat | Status | Evidence |
| --- | --- | --- | --- |
| E | A fooled model widens what it approves | Prevented | An approver issues only inside a bound a person signed (`a_fooled_decider_never_widens_the_bound`). |
| S | A model's own risk rating is taken as authority | Prevented | AWS's own flags decide the band and overrule the model (`a_models_band_is_overruled_and_only_its_probability_counts`). |
| I | A secret read approved as a mere read | Prevented | Secret reads go to a person (`secret_reads_go_to_a_person_although_aws_calls_them_reads`). |

### 4. Log, witnesses and anchors

| | Threat | Status | Evidence |
| --- | --- | --- | --- |
| T | History rewritten, or two histories shown | Prevented, for a verifier with independent witnesses | A checkpoint is trusted only with a quorum of the verifier's witnesses, who cosign only consistent states and refuse a second history under the same key (`a_witness_refuses_a_second_history_under_the_same_key`). |
| T | The same, where the only witness is local | **Open** | `remit init` makes a local witness on the agent's machine; whoever controls the machine can recreate the log and have it cosigned (known gap 6). |
| S | A checkpoint trusted on the log's key alone | Prevented | New: a trust policy with quorum 0 is refused. |
| T | A proof presented for a chain it does not cover | Prevented | Leaves are recomputed from the chain's own bytes. |
| T | The chain file swapped between being checked and being proven | Prevented | New: `remit run` and `remit mcp` prove the bytes they planned from, not a second read of the file. |
| R | A rewrite past an anchored checkpoint | Detected, as far as the verifier keeps the anchors | Consistency with each kept checkpoint is checked; new: a directory with no anchors, or a receipt of an unknown kind, fails, and times are read from the token, not the operator's receipt. Whoever can delete the anchors can delete what they show, so a verifier keeps its own copies (known gap 8). |
| R | A timestamp authority's or Bitcoin's attestation forged | Accepted | Checked with the authority's own tools (`openssl ts -verify`, `ots verify`), and `verify-anchors` says so. |
| I | An account number published in the tiles | Prevented | New: `publish-log.sh` searches the tiles, which carry whole warrants, as well as the checkpoint; results are never published. |
| D | A witness is down | Accepted | The log goes on and is cosigned later (`a_witness_that_is_down_does_not_stop_the_log`). |

### 5. Broker and AWS enforcement

| | Threat | Status | Evidence |
| --- | --- | --- | --- |
| E | A session broader than its warrant | Prevented by AWS; Detected | The session policy is the warrant compiled verbatim with an `aws:CurrentTime` window, and the reconciler compares the recorded policy byte for byte (`a_broader_policy_under_a_real_warrant_id_is_caught`). |
| E | A session that outlives its warrant | Prevented; Detected | Duration is at most the role's maximum and the warrant's end less 60 s; the first live session's one-second overrun was caught (`the_first_live_session_outlived_its_warrant_by_one_second_and_was_caught`). |
| S | Someone with the broker's credentials opens sessions directly | Detected | New: a creation must come from a named broker, through `AssumeRole`, with exactly the five parameters the broker passes, so a copied policy with `PolicyArns` or session tags is caught; creations are recognized by the role AWS recorded, not the requested spelling; and every action must join by access key to a creation the run saw and checked (`a_session_created_with_anything_the_broker_never_passes_is_caught`, `a_session_on_a_managed_role_is_recognized_however_the_request_spells_it`, `an_action_by_a_session_whose_creation_was_not_seen_fails_the_run`). Prevention needs the credentials out of the agent's reach (known gap 3). Unverified: whether CloudTrail records `policyArns`; one `AssumeRole` with it settles that. |
| E | A resource policy grants a session more than its warrant | Detected where recorded | Known gap 1. Seen for real on 2026-09-28: the AWS-managed CodeCommit key's policy let CodeCommit decrypt for a reader session whose warrant grants no `kms:Decrypt`; being a service's call, it is counted under calls made on the session's behalf. |
| E | A session reaches another role by chaining | Prevented at issuance; Detected | `sts:AssumeRole` is an escape grant; new: a warrant's identifier on a session of any role is treated as the warrant's work and fails the join (`a_warrant_identity_on_a_chained_role_is_still_the_warrants_work`). |
| I | The command the broker runs sees the session's credentials | Accepted | It must, to act; they are the warrant's, last at most an hour, and everything done with them is recorded under the warrant's identifier. The program can print them (`aws configure export-credentials`), and through `remit mcp` that output reaches the agent. |
| D | STS throttles or is down | Accepted | Fails closed: no session. |

### 6. Agent host: `remit run`, `remit mcp`, the plugin and the hook

| | Threat | Status | Evidence |
| --- | --- | --- | --- |
| E | The agent reads the broker's credentials | Prevented with the broker service, which leaves none to read (new); **Open** otherwise | `remit mcp` runs as the agent's user, and a process of that user can read its environment from `/proc/<pid>/environ` (reproduced by the red team); a child can also open `~/.aws/credentials` by path, since only the environment is closed (known gap 3). |
| E | The agent runs its own program under a name `--allow` permits | Prevented | New: each `--allow` entry is resolved to its canonical file when the server starts, and only those files run (`only_the_allowed_files_run_whatever_they_are_called`). |
| E | An allowed program does more than expected (`aws` aliases run shell commands) | Accepted | The allow list chooses which program starts, not what it does; whatever it does in AWS runs under the session. |
| S | The agent replaces its current warrant with another logged one | Prevented with the broker service: only the subject's key can use a warrant (new, `only_the_warrants_subject_can_use_it`) | The bearer problem (known gap 5). |
| S | The agent starts `remit run` or `remit mcp` with trusted roots and a log policy of its own | Prevented with the broker service, whose trust is its own (new, `a_warrant_the_agent_signed_and_logged_itself_is_refused`); **Open** otherwise | Reproduced: a warrant for `iam:*`, signed and logged by the agent, passed every check (crossing X5, known gap 10). |
| T | The agent points the broker's `AssumeRole` at a server of its choosing | Prevented | New: endpoint overrides from the environment or a profile are refused (`an_endpoint_override_is_refused_before_any_call`). |
| E | The agent runs `aws` without the hook noticing | Accepted | The hook is a guide rail, not a boundary; the red team bypassed it fifteen ways, as expected. |

### 7. The provider's record and the reconciler

| | Threat | Status | Evidence |
| --- | --- | --- | --- |
| R | A managed action with no warrant | Detected | `managed_actions_without_a_known_warrant_are_caught`. |
| E, R | A managed action that names no resource and that no grant covers | Detected | Was not: the red team reproduced a `complete` over `iam:CreateAccessKey` under a warrant for `s3:GetBucketLocation`. New: such an action is outside the warrant (`an_event_that_names_no_resource_fails_unless_a_grant_names_its_action`). |
| E | An operation whose permission has another name hides from, or falsely fails, the cross-check | Detected | New: the actions that authorize an event come from AWS's service reference for every service (499 operations differ), with S3's exact table first and CloudWatch's `monitoring` source mapped; a difference none of them knows fails closed (`an_event_is_checked_against_the_action_that_authorizes_it`). |
| S | A session creation disguised by spelling the role differently | Detected | New, as in component 5. |
| R | A session whose creation the run never saw: another region's STS endpoint, before the window, a chained role | Detected | New: the access-key join; creations are gathered from before the window as far back as the roles' longest session. |
| E | A trust policy that admits more than the broker (`sts:Assume*`, another account, a federated principal) | Detected | Was not; new: actions are read with IAM's wildcards and only the brokers may be admitted (`a_trust_policy_that_admits_anyone_but_the_broker_fails_the_run`). |
| S | The reconciler's reads sent to a server of the caller's choosing | Prevented | New: reproduced with a local listener receiving the reconciler's `GetRole`; endpoint overrides are now refused (crossing X12). |
| S | A trail validated under CloudTrail keys the caller made up | Detected by a verifier | New: each region's coverage records the fingerprints its chain verified under and the newest digest, to compare with the keys AWS publishes (crossing X12). |
| T | The reconciler, its inputs or its key are the agent's | Prevented where it runs off the agent's system (`deploy/github/`, new); **Open** on a single-user machine | On a single-user machine they are (known gaps 10 and 11); its result is then the agent grading itself. |
| T | The record altered | Detected with a validated trail | Digest chain verification (SPEC 6.7); from event history the verdict can only be `complete, unvalidated`. |
| R | The trail's scope narrowed: event selectors, global service events, regions | **Open** | Integrity is checked, scope is not (known gap 9); the access-key join now catches a missing creation, not a missing action. |
| R | Events delivered after the settling period | Accepted | Stated in every result; re-running the window confirms it. |
| R | A service acting in a session's name | Accepted | SPEC 6, assumption 4. New: recognized by `invokedBy` or by the service as the source address, as CodeCommit's forward-access calls were recorded, and counted by service and action instead of failing as unseen sessions. |
| D | An agent forces `incomplete` with actions the checks cannot read | Accepted | Fails closed; S3 object events are no longer checked against the bucket that contains them (the red team's claim that such events list the bucket is unverified, and the rule is harmless if they do not). |

### 8. Results and verification

| | Threat | Status | Evidence |
| --- | --- | --- | --- |
| S, T | A forged or edited result | Prevented | Signed over its exact bytes in the `REMITRv1` domain; `verify-report` checks the signer and the signature before parsing (a tampered report fails, checked 2026-09-28). |
| R | A verdict read without what qualified it: event history, a short settling period, fewer regions, refused inputs | Prevented | New: `verify-report` prints the source, settling period, run time, each role's trust policy, refused inputs, findings by kind and calls made on a session's behalf. |
| I | A result that names resources | Accepted | Counts by action never name resources, but findings do; results stay private, and only their signed commitments enter the public log. |
| S | The reconciler's key misused | Accepted | It is not an issuing key; anyone with read access to the record can re-run the window and compare. |

### 9. Build and distribution

| | Threat | Status | Evidence |
| --- | --- | --- | --- |
| T | A release binary replaced | Detected | SHA-256 sums, Sigstore build provenance (`gh attestation verify`), CycloneDX SBOM. |
| T | A build tool compromised to alter binaries or attestations | Prevented, as far as pinning reaches | New: Zig and cargo-zigbuild install by wheel hash, and the SBOM tool, at a fixed version, runs in a job with no permission to write the release or sign for it. |
| T | The installed binary replaced after installation | Prevented in the production layout, root-owned in the agent's own system (new); **Open** on a single-user machine | On a single-user machine the agent's user owns `~/.local/bin/remit`; nothing checks it again (crossing X15, known gap 11). |
| E | A vulnerable dependency | Detected for known advisories | `cargo audit` on every push and weekly; RustSec advisories fixed in 0.1.2. |

### 10. Project state on disk (`remit init`, `remit task`)

| | Threat | Status | Evidence |
| --- | --- | --- | --- |
| T | The agent edits or recreates the log, the witness state or the trust policy | Prevented in the production layout, where the log is the issuers'; **Open** in the single-machine one | They live in the project directory the agent works in, under its user (known gap 6); the red team deleted and recreated the log and had the local witness cosign the new history. |
| I | Keys committed to the repository | Prevented | `remit init` writes `.gitignore` with `*.key`. |

## Boundaries, crossing by crossing

Added the same day, after the owner asked whether the boundaries between the components had been reviewed: they had not been, one by one.
The STRIDE tables above ask what can go wrong inside each component; this section asks, for every arrow that crosses a zone, what crosses it, what the receiving side checks, and who controls the input in practice.
It found two flaws the component review missed, both fixed, and one that changes the verdict.

### Who holds each zone

A zone is only a boundary if a different principal holds it.
On a machine where the agent runs as the person who set Remit up, which is what `remit init` makes, the zones collapse:

| Zone | Meant to be held by | Held on a single-user machine by |
| --- | --- | --- |
| Person with the issuing key | The people who issue | The agent's user: `~/.config/remit/root.key` |
| Public log | The log operator and independent witnesses | The agent's user: the log key, the local witness key and the trust policy file |
| Agent's machine | The agent | The agent's user |
| Broker | A separate identity (known gap 3) | The agent's user: the broker's key, and the trusted roots and log policy it is given |
| AWS account | AWS | AWS |
| Reconciler and verifiers | Someone other than the agent | The agent's user: the binary, the reconciler's key and every input it trusts |
| Releases | GitHub's build, attested | GitHub's build; after installation the binary is a file the agent's user can replace |

Every file listed was checked on 2026-09-28 and is owned by the agent's user.
So on such a machine there are three principals, not six: the agent's user, AWS, and the outside world (GitHub, the timestamp authority).
Only the boundaries with AWS and with the outside world are held by someone other than the agent.
It is often worse than one user: membership of a group such as `docker` is root without a password, and on Windows, WSL interop lets any Linux process run programs as the Windows user.
A second user on the same system is then no boundary either; the agent needs a system of its own (`docs/PRODUCTION.md`).

### Each crossing

| # | Crossing | What crosses | What the receiver checks | Status |
| --- | --- | --- | --- | --- |
| X1 | Issuer to log | A signed warrant | That it decodes; the log is a record, not a judge, and accepts any chain. Roots are enforced where a warrant is used (X5) and reconciled (X13). | Prevented as designed; the log key's custody is known gap 6 |
| X2 | Model approver to log | A warrant the approver signed for a request the agent wrote | That the request fits a bound a person signed; a fooled model cannot widen it (component 3) | Prevented |
| X3 | Log to witnesses | A checkpoint | The log's signature, consistency with every checkpoint cosigned before; forks refused | Prevented where the witnesses are other parties; the default local witness is the agent's (gap 6) |
| X4 | Log to anchors | A checkpoint's digest | The authority timestamps it over HTTPS; remit confines receipts to the anchors directory and checks the token's digest | Prevented; keeping the anchors is gap 8 |
| X5 | Log and issuer to the broker (`remit run`, `remit mcp`) | The chain, its proof, the trusted root keys and the log's trust policy | The chain verifies to a trusted root and is proven logged under the policy, but **the trusted roots and the policy are whatever the caller passes**. Reproduced: a warrant for `iam:*` and `s3:*`, signed by a key the agent made and logged in a log the agent made, passed every check and stopped only for want of credentials. The broker service (SPEC 8.4) holds its own roots, log policy and roles, and serves only the warrant's subject: the same minted warrant is refused, tested through the Lambda binary itself. | Prevented with the broker service (new); **Open** where `remit run` holds the broker's key itself, known gap 10 |
| X6 | Agent to `remit mcp` | Tool calls over stdio | Arguments validated; programs resolved to allowed files. The server's own configuration (chain, roots, policy, allow list) comes from the agent's MCP settings, as in X5. | Prevented for the calls; with `--broker-function`, sessions are the service's decision (new) |
| X7 | Broker's credentials to the broker | An access key, from the environment or a profile | Nothing; the process is the agent's user | Prevented with the broker service: the agent holds no broker key, only one that can ask (new); **Open** otherwise, known gap 3 |
| X8 | Broker to STS | `AssumeRole`, signed with the broker's key | TLS to AWS. **Was not checked: `AWS_ENDPOINT_URL` or a profile's `endpoint_url` sent the call wherever the caller chose.** Now refused. | Prevented (new) |
| X9 | STS to the command | The session's credentials, in its environment | Nothing, and nothing can: the command is the agent's, and the credentials are the warrant's | Accepted |
| X10 | Session to AWS services | API calls | AWS enforces the session policy; resource policies add to it (gap 1); services acting in the session's name are counted (component 7) | Prevented, with gap 1 |
| X11 | AWS to CloudTrail | The record | Internal to AWS; delivery time and the trail's scope are the reconciler's concern | Accepted; scope is gap 9 |
| X12 | CloudTrail to the reconciler | Events, from event history or trail files | TLS; for trail files, AWS's signed digest chain. **Was not checked: the endpoint override of X8 also redirected the reconciler's reads (reproduced with a local listener receiving its `GetRole`), and the CloudTrail public keys that validate the chain are a file the caller supplies, not recorded in the result.** The override is now refused and the key fingerprints are in the result. | Prevented for the endpoint (new); keys Detected by a verifier who compares the fingerprints (new) |
| X13 | Log and roots to the reconciler | The logged warrants, the trust policy, the trusted roots | Chains verify to the roots and are established at a trusted checkpoint, but the roots and policy are the caller's, as in X5 | Prevented where the reconciler runs with its own anchors (`deploy/github/`, new); **Open** where the agent starts it, known gap 10 |
| X14 | Reconciler to verifiers | A signed result | The signature, in its own domain, under a key the verifier names; the verifier must know that key from somewhere the agent cannot write | Prevented, given the key's custody |
| X15 | Release to the installed binary | The `remit` binary | Checksums and provenance when it is downloaded; after that it is a file, and on a single-user machine the agent's user can replace the program that checks it | Prevented where it is installed root-owned in the agent's own system (`docs/PRODUCTION.md`, new); **Open** on a single-user machine, known gap 11 |

### What this changes

On a single-user machine, Remit's local checks guide an agent that is not trying to get around them: they refuse a chain that is not logged, a grant that escapes the warrant, a program not allowed.
They do not bind an agent that is, because every file and process they rely on is the agent's own.
What still holds there is what AWS holds: the role's own permissions are the most any session can do, and CloudTrail records every call, the agent's own sessions included.
A reconciler run somewhere the agent cannot reach, with its own binary, trust anchors and key, would catch the agent's own warrants as unwarranted (their identifiers name no warrant in the real log) and its own sessions as mismatches.
A reconciler run on the same machine is the agent grading itself: its result is true only as far as the agent is honest.

## Does it hold up?

Every claim below assumes the zones are held by different principals (assumption 7).
On a single-user machine they are not, and the claims reduce to what AWS enforces and records (see "What this changes").

**Authorized** holds against a misbehaving agent (A1) and an over-delegating one (A3) when the issuing key and the broker's credentials are out of the agent's reach.
It does not hold against an agent that can read the issuing key, which the default single-user setup allows (known gap 6), or that uses another agent's valid warrant (known gap 5).
A warrant signed with a stolen key is public in the log, where people can see it, but the log does not yet prove it was there before the session (known gap 7).

**Bounded** holds for the agent's own sessions: AWS enforces the compiled policy, and nothing in this review found a way to make AWS enforce less.
The exceptions are resource policies that name the session or grant to everyone, which AWS applies on top (known gap 1), and grants that let work leave the warrant, which now need `--allow-escape` at issuance.

**Complete** now holds, for managed principals in the regions and event classes the record covers, against every way the red team produced a false `complete` from ordinary AWS behaviour: actions with no resource, sessions opened with extra parameters or by anyone but the broker, sessions whose creation the run did not see, chained roles, and loose trust policies.
Each is a test that fails on 0.1.3.
Run over the day's real record on 2026-09-28 (1,638 events), the reconciler joined all 19 warranted sessions and 121 warranted actions to checked creations, and counted 8 CodeCommit decrypts as calls made on a session's behalf.
That run was on the agent's own machine, so it shows the checks work on real data, not that the agent was honest (known gap 11).
It still depends on the trail's scope, which it does not check (known gap 9).

Since the boundary review, what closes the most of what is Open is built: the broker service (SPEC 8.4), the off-host reconciler (`deploy/github/`), and a production layout that gives the agent a system of its own (`docs/PRODUCTION.md`).
In that layout, Authorized and Bounded hold against an agent that tries (it can neither sign itself a warrant the broker accepts nor use another agent's), and Complete holds because the judgement runs where the agent cannot reach; the remaining limits are known gaps 1, 2, 4, 7, 8 and 9.
The design those changes follow is two moves off the agent's host.
The broker becomes a separate service with its own identity, its own trusted roots and log policy, no static key, and a check of a signature by the warrant's subject before it opens a session: that closes known gaps 3 and 10 for the broker, and makes gap 5 fixable.
The reconciler runs elsewhere, with a binary, trust anchors and a key the agent cannot reach: that closes gaps 10 and 11 for the judgement, so that a `complete` means something even about an agent that tried.

## Assumptions

Remit's guarantees depend on these, and each result restates the ones it relied on.

1. The cryptographic primitives hold: SHA-256 collision resistance, and the signature scheme (ADR 0003).
2. The cloud provider enforces its own policies as documented, and its audit record is written by the provider.
3. Issuing keys are held by the people they name, out of any agent's reach.
4. The broker's credentials are out of the agent's reach, so that only the broker opens sessions on the managed roles; the reconciler detects when this does not hold (known gap 3), but cannot prevent it.
5. Clocks are within 60 seconds of AWS's. The broker keeps that margin between a session's end and its warrant's end (SPEC section 8.1), and the reconciler checks every session against AWS's recorded time.
6. A verifier trusts witnesses the log's operator does not control, and keeps its own copies of anchors.
7. The zones in the diagram are held by different principals: the broker, the log, the reconciler and whoever holds the issuing key are not the agent's operating-system user. Where they are, the claims reduce to what AWS enforces and records.

## Known gaps

Limits of the design as built, stated so that no one has to find them.

1. **A resource-based policy can grant around a warrant.** AWS: "A resource-based policy can specify the ARN of the session as a principal. In that case, the permissions from the resource-based policy are added after the session is created. The resource-based policy permissions are not limited by the session policy" (IAM user guide, session policies). When the record covers the action, the reconciler reports it as outside the warrant; a data event is recorded only where data events are configured (SPEC 6, assumption 2). Detected where recorded, never prevented.
2. **A warrant cannot be revoked before it expires.** A logged warrant is honoured until its window ends, and credentials already issued stay valid until they expire, at most the role's maximum session and never later than 60 seconds before the warrant ends (SPEC 8.1). Short windows are the mitigation until revocation exists.
3. **The broker's credentials within the agent's reach.** *Closed by the broker service (SPEC 8.4) where it is used: the agent holds no broker key, only one that can ask. Open where `remit run` holds the key itself.* When `remit run` or `remit mcp` runs as the agent's user, the agent can read the broker's credentials (from the environment, `/proc`, or `~/.aws/credentials`) and call `AssumeRole` itself. Since this review, the reconciler catches every such session it can see: one with any parameter the broker does not pass, a caller other than the broker, a policy or duration that is not its warrant's, or actions whose creation it did not see. Detected, not prevented; prevention is a broker on another identity or host.
4. **Escape grants are the issuer's choice.** `--allow-escape` issues a warrant whose grants let work leave it; the warrant then bounds the call that does so, not what follows.
5. **A warrant is a bearer credential.** *Closed by the broker service: a request must be signed by the key the warrant names as subject. Open where `remit run` holds the broker's key itself, which can open a session for any warrant.* Nothing binds the session to the warrant's subject: whoever can reach a broker can use any valid logged warrant, and the result attributes the work to that warrant's subject. The fix is a broker that requires a fresh signature by the subject's key over the warrant identifier, a nonce and the time, and records the subject in the session.
6. **The default setup keeps the log, its local witness and the issuing key under the agent's user.** *Stated by `remit init` itself now, which points to `docs/PRODUCTION.md`; closed by deployment, not by code.* `remit init` is for trying Remit on one machine. There, the agent can recreate the log, lower the trust policy, or sign with the issuing key, and `init` says that its permission rules do not stop a script. In production, the issuing key belongs to people, the log to another identity, and the witnesses to other parties.
7. **The log does not prove a warrant was logged before its session.** The broker refuses unlogged warrants, but someone with an issuing key and the broker's credentials can open a session under a warrant's identifier first and log the warrant later. The fix is to require each warrant's entry in a checkpoint whose witness cosignatures are timestamped before the session's creation.
8. **Anchors protect only the verifier who keeps them.** Whoever can delete the anchors directory can delete what it shows. The fix is to publish receipts as record entries in the log, so that witnesses hold them.
9. **The trail's scope is not checked.** A validated trail proves its files are whole, not that it records every region, global service events, and the data events the warrants concern. An administrator who narrows it (A6) narrows what `complete` means without a finding. The fix is to read the trail's configuration (`GetTrailStatus`, `GetEventSelectors`) on every run and state it in the result.
10. **The broker and the reconciler take their trust anchors from whoever starts them.** *Closed for the broker by the broker service, and for the reconciler by running it with its own anchors (`deploy/github/reconcile.yml`), which also fetches CloudTrail's keys itself. Open wherever the agent starts either.* The trusted root keys and the log's trust policy are arguments, and the CloudTrail public keys a file; when the agent starts `remit run`, `remit mcp` or `remit reconcile`, it chooses what they trust. Reproduced on 2026-09-28 (crossing X5). The fix is that each component owns its trust configuration on its own side of the boundary: a broker service configured by the issuers, a reconciler whose roots and policy are committed where it runs, and CloudTrail keys fetched by the reconciler and recorded in the result (the recording is done; the fetching is not).
11. **On a single-user machine, the agent is every local principal.** *Closed by deployment (`docs/PRODUCTION.md`): no code can make one system two principals.* The agent's user owns the issuing key, the log and witness keys, the broker's key, the reconciler's inputs and key, and the installed binary. Remit's local checks then guide an agent but do not bind one; the role's permissions and CloudTrail still do. The fix is separate principals: the broker and the reconciler off the host, the log's witnesses run by others, and the binary installed where the agent's user cannot write.

## Out of scope

- Whether an authorized action was the right one. Remit records who allowed it.
- Side channels on the agent's host.
- The provider's internal integrity beyond what it documents and signs.
- Denial of service against the broker or the log, beyond failing closed: without the broker, an agent gets no credentials.

## Failure principles

- **Fail closed.** A warrant that cannot be verified, compiled within limits, or chained is refused; an event the reconciler cannot read fails the run rather than passing.
- **Never round up.** A limit that cannot be expressed exactly is a refusal, never an approximation, because an approximation is a different grant.
- **Say what was not checked.** A result that relied on an assumption it could not verify says so in the result, and a verification prints what it did not verify.
