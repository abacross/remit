# 0005: Business model, and finding design partners without the owner in the loop

Date: 2026-09-24. Status: accepted by the owner on 2026-09-24, subject to the one-time setup in section 6.

## Context

Remit has to be adopted to matter and has to earn money to last.
Its claim is about trust, so anything that looks like a trick to win attention undermines it: the owner declined a broad awareness campaign on 2026-09-24 for that reason.
Remit is built and operated by an AI agent under human approval, and the owner's standing instruction is to be out of the loop as much as possible, with the agent acting with caution and authority.

## Decision, part 1: what is free and what is sold

**Everything needed to trust Remit is open source (Apache-2.0):** the warrant format and `remit-core`, the broker, the reconciler, the command-line tool, and the verifier that checks any report offline.
A trust product with closed verification contradicts itself, and the open code is the adoption engine.

**What is sold is independence.** A completeness claim is weak when the party making it also keeps the record, so a customer cannot be their own witness.
Abacross sells being the party that is neither the customer nor the customer's agent:

| Offer | What the customer gets | Price shape |
| --- | --- | --- |
| Team | Hosted continuous reconciliation across accounts, and the independent witnessed log | Flat monthly, per organization |
| Regulated | Team, plus a signed monthly completeness report written for auditors, and retention the customer sets | Flat monthly, per organization |
| Onboarding | Warrant design, trust policies and rollout in the customer's accounts; today's audit engagement, repurposed | Fixed fee per engagement |

Prices are flat, never metered per event, call or token: a customer should know what they have committed to.
The numbers start from the attestation tiers already published on `/attest/` and are set in a later decision, not here.
The operations code of the hosted service may stay private; nothing a customer needs in order to verify a result ever is.

## Decision, part 2: design partners

Before building the hosted service in earnest, Remit needs evidence that the problem is real to people who would pay, and three teams willing to run it.

**The offer**, fixed here so the agent can make it without asking:

- Remit Team, free, for six months, and onboarding help by email.
- In exchange: a short reply every few weeks on what worked and what did not, and permission to describe the partnership publicly, named or anonymized, at the partner's choice.
- No contract, no money either way, no access by Abacross to the partner's systems: the partner runs Remit in their own account.
- Either side can end it at any time, by email.

**Who is approached:** teams that are visibly running AI agents against AWS, found from public sources (their own blog posts, open repositories, public talks), whose problem Remit addresses on the evidence of what they published.

**The sequence:**

1. Problem validation now, before Remit is usable: a short, specific email asking whether the team can prove what their agent did and that it did nothing else, and how they would want to. Replies are the data.
2. The free readiness check as the first concrete step for anyone who answers.
3. Partnership when the broker and the reconciler run end to end (Remit milestones 2 and 3), offered first to those who replied.

## Decision, part 3: the agent's standing authority

Once the setup in section 6 is done, the marketing agent runs the program without asking, within these limits.

**It may:**

- find candidates in public sources, and recipients' addresses only where an organization publishes an email address for contact (a website's contact page, a GitHub organization's public email); never an address scraped from commits or guessed, never a security or vulnerability-report address, and never a contact form: forms are for customers, not for outreach (owner, 2026-09-24);
- send at most ten messages a day, to United States recipients only, each specific to that team and citing the public evidence it was chosen on;
- send one follow-up after seven days without a reply, and nothing after that;
- answer factual questions from what Abacross has already published;
- offer exactly the design-partner terms above, and accept a team that says yes to them.

**It must not, and queues instead:** anything involving money, a contract, an NDA, a security questionnaire, access to anyone's systems, a press or public-speaking request, any claim about Abacross that is not already published, and any complaint.

**Every message says who wrote it.** The agent writes and sends these messages, so the signature says so: "Written and sent by Abacross's operations agent for Mike Oh. A person reads every reply that needs one." It is never signed as if Mike wrote it (owner, 2026-09-24): an agent writing to strangers under a person's name, without saying so, is the opposite of what Remit is for.

**Every message** identifies Abacross as the sender and itself as a commercial message, carries the company's postal address and a working opt-out, and has a subject line that says what it is (FTC, CAN-SPAM compliance guide: "The law makes no exception for business-to-business email", a "valid physical postal address", opt-outs honoured within 10 business days and a mechanism that works for 30 days).

**Opt-outs are automatic.** A reply that asks to stop suppresses the address and its domain the same day, with no human step.

**It stops itself** and queues a decision if a complaint arrives, if more than one message in twenty bounces, or if a recipient's reply suggests the targeting is wrong.
The owner stops everything at any time with `bash scripts/policy.sh ask email.send`.

**Everything is recorded:** each send in the operations journal (hash-chained and anchored), each reply's outcome in the program's report, and a weekly one-line summary in `agents/INBOX.md` that needs no action from the owner.

## 6. The one-time setup that only the owner can do

These are the only owner steps, and none recurs:

1. A postal address for the footer (a registered P.O. box is enough), because the law requires one and the agent cannot invent it.
2. SES production access (lodestar decision 28), because the sending identity is still in the sandbox.
3. Approval to create the inbound path: a receipt rule and a bucket so that replies to `mail.abacross.com` reach the agent, which is what makes automatic opt-outs and unattended replies possible. This is an AWS change and a DNS change.
4. `bash scripts/policy.sh allow email.send`, and the harness line for the sender, because a permission the agent grants itself is not a permission.

## Success, and what would change this

Within 90 days of sending starting: twenty replies that describe the problem in the respondents' own words, collected verbatim, and three teams committed as design partners.
Within six months of a partner starting: at least one partner willing to pay list price for Team.

If fewer than five in a hundred approached teams reply, the targeting or the problem is wrong, and the program stops for a decision rather than sending more.
If partners use the free code and none wants the independent witness, part 1 is wrong, and the business model is revisited before the hosted service is built.
