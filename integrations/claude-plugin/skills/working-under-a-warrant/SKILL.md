---
name: working-under-a-warrant
description: How to do cloud work when your cloud access comes from a Remit warrant. Use before any AWS command, cloud API call or infrastructure change, and whenever a cloud command is refused.
---

# Working under a Remit warrant

You have no cloud credentials of your own.
A person signed a warrant that says which actions you may take on which resources, for how long and why, and Remit's broker gives you short-lived credentials for it, one command at a time.
The cloud records every call you make with the warrant's identifier, and Remit later compares that record with the warrant in both directions.

1. **Start with `remit_warrant`.** Read the grants, the time left and the purpose before planning. Plan only what the grants allow.
2. **Check before acting when unsure.** `remit_check` with one action (for example `s3:GetObject`) and one resource ARN tells you whether the warrant permits it now, and why not if it doesn't.
3. **Run cloud commands with `remit_run`.** Give the program and its arguments as a list, for example `["aws", "s3", "ls", "s3://bucket"]`. No shell, pipes or redirection: process the output yourself. Calling `aws`, `az` or `gcloud` directly through the shell is refused.
4. **When something is refused or denied, stop and say so.** Report which action on which resource was refused and the reason. Never look for another route to the same action: another credential, another tool, or a broader resource. If the task needs more than the warrant allows, the person who signed it decides, not you.
5. **A warrant that is not proven logged is not honoured**, and one that has expired stops working at the next call. Tell the person; don't retry.

What a warrant cannot tell you is whether an action is the right one. It only says who allowed it. Use judgement inside it.
