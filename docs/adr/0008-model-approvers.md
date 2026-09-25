# 0008: Model approvers act only inside a bound a human signed

Date: 2026-09-24. Status: accepted.

## Context

Teams are putting models in charge of approving agent actions.
TypeSafe's Jev, a decision model released in limited early access on 15 September 2026, returns typed verdicts with probabilities and confidence instead of text, and LangChain ships middleware that uses it to "decide whether an agent's tool calls should run".
Open reproductions exist; jeff (MIT) serves the same wire format from a 400M-parameter encoder on local hardware.

Two facts limit what such a verdict can be trusted with.
First, it can be moved: in a published test, Jev's probability of blocking `rm -rf ~/.ssh` fell from 0.76 to 0.48 after one fake field claiming the user had pre-approved it, and TypeSafe says that content "written to adversarially steer the model ... can move the answer" (VentureBeat, 2026-09).
Second, its numbers are not all calibrated: jeff's own source calls its probabilities "score renormalization, not a calibrated posterior", and its published benchmark puts it well behind Jev on judgement tasks.

A verdict that reads the same untrusted context as the agent is advice, however good the model.
What Remit adds is a bound that no verdict can move.

## Decision

An approver is an agent with its own key that holds a warrant from a human, and grants from it by delegation (SPEC section 10).

1. **The human signs the bound.** A warrant whose subject is the approver's key, with `max_depth` at least 1, states the most the approver may ever grant.
2. **The bound is checked before any model is asked.** A request the bound does not cover is refused by the attenuation rule (SPEC section 4), deterministically; no answer from any model can change that. The attenuation theorem then guarantees that everything the approver issues is inside the bound, whatever the model said.
3. **Rules, then the model, then a threshold, all failing towards a person.** Hard rules escalate named action classes outright. The model answers two questions, a risk band and a yes-or-no on running without a person; only an allowed band at or above a threshold issues. An error, a timeout, a malformed answer or a low score escalates. Nothing fails open.
4. **One concrete action per warrant, briefly.** The approver grants exactly one action on exactly one resource, with no wildcards, for a short window inside the bound's, and with no further delegation.
5. **The evidence travels in the warrant.** The model, its answers, the threshold and a hash of the exact input are written into the child warrant's purpose, which the approver's signature covers and the log makes public (SPEC section 9). A reviewer can see why each approval was given without trusting the approver's own records.
6. **Model-agnostic.** The decider is an interface. The first implementation speaks the System One wire format (`POST /v1/systemone`), so it runs against jeff locally at flat cost and against Jev by changing a URL and a key; rules alone, or any other model, fit the same interface.

## Consequences

- An approver fooled by injected text can approve only what a human had already bounded. The worst case is decided when the bound is signed, not when the model is asked.
- Escalations are frequent by design at first. Thresholds are tuned against the decision log (every verdict, allowed or not, with its inputs' hash), not guessed.
- Using Jev itself means a TypeSafe account, per-token billing and request content leaving the machine; for Abacross that is an owner decision, and development runs against jeff.
- The evidence format is part of the purpose text, not a new field, so warrants keep the encoding of SPEC section 3.6.

## What would change it

A decision model whose output could not be moved by the content it judges, which would make the bound less necessary but not unnecessary; or a need for approvals that span several actions, which would need a rule for how far one verdict may reach.
