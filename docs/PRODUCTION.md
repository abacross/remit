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

## With these in place

- A warrant the agent signs itself is refused by the broker service: the service trusts only its configured roots and log.
- A warrant issued to another agent is refused: only its subject's key can use it.
- A session opened some other way, a session policy that differs from its warrant, or an action outside a warrant fails the next reconciliation, which the agent cannot change.
- What remains is written in the threat model's known gaps: resource policies that name a session, no revocation before a warrant expires, and the trail's scope.
