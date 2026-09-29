# 0010: Remit Assurance: independence as a service, without custody, per governed agent

Date: 2026-09-29. Status: accepted for design by the owner on 2026-09-29 (Abacross decision 59); the service is built after design partners confirm what they would pay for.
Supersedes the offer table of ADR 0005 part 1; its principles stand.

## Context

ADR 0005 sells independence: a customer cannot be its own witness.
It priced that flat per organization and described Team as hosted reconciliation.
Two things changed.
First, reconciliation belongs in the customer's own account: it reads CloudTrail, and a service that holds CloudTrail data triggers data-location, outsourcing and cloud-certification rules (the Korea research behind Abacross's business plan) and SOC 2 scope everywhere.
Second, a flat price per organization does not grow as a customer hands more work to agents, which is the one thing every customer is doing.

So the service must do what a customer cannot do alone, from data that identifies nothing, and be priced by what grows.

## Decision

**Remit Assurance is a multi-tenant service that is each customer's independent witness and verifier.**
The customer runs the broker and the reconciler in its own accounts (`docs/PRODUCTION.md`).
The service receives two things, neither of which names an account, a role, a resource or a person:

1. **Checkpoints to cosign**, over the C2SP witness protocol `remit witness serve` already speaks: a log's size, root and signature.
   The service is a witness in the customer's log trust policy, beside any other.
2. **Signed summaries**, one per reconciliation run, described below.

From them it:

- **cosigns** each checkpoint consistent with every one it cosigned before, and refuses a second history (the witness's existing rules);
- **verifies** each summary's signature under the customer's registered reconciler key, and that the log checkpoint the summary names is one it cosigned;
- **alerts** the customer on an incomplete verdict, on a day with no summary (a reconciler that stopped is a finding too), and on a refused checkpoint;
- **attests** monthly: a document signed by Abacross in its own domain (`REMITAv1`) stating, for the tenant and the month, which days were reconciled and with which verdicts, which were not, that the log stayed consistent, and how many agents were governed.

### The summary

The full result (SPEC 6.6) names the customer's roles, resources and principals, and stays with the customer.
The reconciler also writes a **summary**, signed with the same key in its own domain (`REMITSv1`), holding only:

- the window, the run time, the settling period and the event source;
- the verdict, and the number of findings of each kind;
- the number of regions and managed roles covered, not their names;
- the log checkpoint it relied on (origin, size, root);
- the SHA-256 of the full result, so that the full result, shown later to an auditor, is provably the one the summary stands for;
- the key identifiers of the warrants' subjects that held sessions in the window: public keys, which identify agents to the customer and to nobody else.

The customer can check before sending that the summary says nothing more: it is a fixed format, and `remit verify-summary` prints it.

### The unit: governed agents

A **governed agent** is a distinct subject key that held a session under a warrant in the month, counted from the summaries the service verified.
The customer's bill is therefore computed from what the service already checks, needs no data beyond the summaries, and grows as the customer's use of agents grows.
It is sold in annual bands of that count (Abacross's business plan, section 2), never metered per call or event.

### How a tenant authenticates

A tenant registers its log's verifier key and its reconciler key.
Every request is signed by one of them; there are no passwords and no API tokens to steal, and a summary that is not signed by the registered reconciler key is refused.

### What it runs on

Serverless in Abacross's own AWS account: functions behind API Gateway, a table per concern (tenants, witness state, summaries), and an append-only bucket with object lock for attestations.
The witness state is the one thing that must never go backwards; it is kept with conditional writes so that two requests can never both extend it.
Abacross's attestation key is held in a hardware-backed key store, not in a file.
None of it is on the operator's machine, and the agent that operates Abacross holds no key that can sign an attestation.

### What it needs before enterprises buy it

- A SOC 2 Type II report: the service holds no CloudTrail data, but a hosted service is asked for one regardless.
- Its own threat model, in the same form as `docs/THREAT-MODEL.md`, before the first tenant.
- The witness as an operator in the public witness network (Abacross decision 43), so that customers can also trust witnesses Abacross does not run.

## Order of work

1. **Now:** this design; the summary format and `remit verify-summary` in Remit, since they are useful without the service (a customer can hand summaries to any verifier).
2. **With design partners:** Abacross runs the witness and verifies their summaries by hand and with the CLI, and writes the first attestations manually, to learn what they rely on.
3. **After that:** the hosted service, then its listing on AWS Marketplace as a SaaS contract in the bands.

## Consequences

- Customers keep every identifier they have; Abacross's promise is simple everywhere, and the Korean route (the customer's own account, no data abroad) holds.
- The price grows with the thing customers are growing, with no engagement staff behind it.
- The service can be offered by others too: the summary and the witness protocol are open, and a partner or an auditor can verify and attest the same way; what Abacross sells is being a known, independent, audited party that does.
- If a customer's reconciler lies, the summary lies: the service verifies signatures and consistency, not the customer's AWS record. That is why the reconciler must run where the customer's agents cannot reach it (`docs/PRODUCTION.md`), and why an attestation says whose reconciler signed each summary.
