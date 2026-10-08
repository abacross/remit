# Remit in production

`remit init` sets Remit up on one machine, which is right for trying it and wrong for relying on it.
There, the agent runs as the person who set it up, so the issuing key, the log's keys, the broker's credentials and the reconciler are all within the agent's reach, and Remit's checks cannot bind an agent that tries to get around them ([threat model](THREAT-MODEL.md), known gaps 10 and 11).

Remit's claims hold when each part is held by a principal the agent is not.

`deploy/aws/setup.sh` deploys the AWS side in order, as a person with administrator rights: the broker's verified code, the broker service, one role per kind of work that only the service may assume, and the off-host reconciler's role (`DRY_RUN=1` prints each command first).
The reconciler's repository is set up with `deploy/github/README.md`.

| Part | Where it runs | What the agent holds |
| --- | --- | --- |
| Issuing | The issuers' own machines; the key never enters the agent's system | Nothing |
| Log | Operated by the issuers; cosigned by witnesses run by other parties | Nothing |
| Broker | A service with its own trust configuration, which opens a session only for a warrant's subject (SPEC 8.4; `deploy/aws/broker-service.yaml`) | Its own Remit key, which proves it is the subject, and a credential that can only ask the service |
| Reconciler | Somewhere the agent cannot write: a scheduled job with its own trust anchors and key (`deploy/github/`) | Nothing; it reads the results |
| The agent | A system of its own: its own machine, VM or container, with no administrator rights and none of the people's credentials | Only the above |
| The binary | Installed where the agent cannot replace it, from a release whose checksum and provenance were checked | Nothing |

## The only path

The table above holds only if the broker is the agent's only way to act in the account.
An agent that can reach a second AWS credential does not need to get around Remit; it can simply not use it.
So every principal that can act in a governed account should be in one of four categories ([ADR 0011](adr/0011-the-only-path.md)):

| Category | How it acts | Checked today |
| --- | --- | --- |
| Agents | Through the broker, on managed roles whose trust policy admits only the broker | Yes, by every reconciliation |
| People | Federated sign-in with a security key or passkey; no IAM user access keys | Not yet (`remit inventory`, ADR 0011) |
| Pipelines | Roles that trust one OIDC subject, a repository and branch; no stored key | Not yet (`remit inventory`) |
| Service roles | Assumable only by an AWS service principal | Not yet (`remit inventory`) |

Until those checks are built, check by hand before relying on Remit:

- No IAM user in the account has an active access key, except a documented break-glass user if you keep one.
- The agent's system has no AWS credential variables, no shared credentials or config files, no web identity token, and no route to the instance metadata service or a container credentials endpoint.
- Every role's trust policy admits a broker, an OIDC subject, an AWS service, or federated people, and nothing else.
- Service control policies deny creating IAM users and access keys, changing managed roles' trust policies, and stopping or narrowing the trail, except to named roles.
- The trail is an organization trail kept in an account the workloads cannot change.

## With these in place

- A warrant the agent signs itself is refused by the broker service: the service trusts only its configured roots and log.
- A warrant issued to another agent is refused: only its subject's key can use it.
- A session opened some other way, a session policy that differs from its warrant, or an action outside a warrant fails the next reconciliation, which the agent cannot change.
- What remains is written in the threat model's known gaps: resource policies that name a session, no revocation before a warrant expires, and the trail's scope.
