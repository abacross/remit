# 0009: An MCP server and an agent plugin, which reach cloud credentials only through a warrant

Date: 2026-09-26. Status: accepted.

## Context

Agents are built with frameworks, and most of them take tools over the Model Context Protocol (MCP): Claude Code and the Claude Agent SDK load MCP servers and plugins, and other frameworks do the same.
Today an agent reaches Remit only through `remit run`, a command a person or a script wraps around the agent's own commands.
For Remit to be the default way an agent gets cloud credentials, it has to be a tool the agent can call, and it has to arrive in the form agent builders already install.

The risk is obvious: a tool that hands an agent cloud access is exactly the kind of thing that could widen authority by accident.
So the question is not what the server can do, but what it must never do.

## Decision

`remit mcp` is an MCP server over standard input and output, in the same binary as the rest of Remit, configured at launch exactly as `remit run` is: the warrant chain, the trusted roots, the role, the log's trust policy and the chain's logged proof.
It offers three tools:

- **`remit_warrant`**: what the agent may do, for how long and why, with the chain verified and its logging checked.
- **`remit_check`**: whether one action on one resource is permitted now, and if not, why: outside the time window, not logged, or no grant allows it. It is the same decision the warrant makes (SPEC 3.4), offered so an agent can plan inside its bounds instead of discovering them by failure.
- **`remit_run`**: one command, given as a list of arguments and never through a shell, run exactly as `remit run` runs it: the chain verified against the roots, proven logged (SPEC 9.3), credentials from the broker with the warrant's identifier as the session's source identity, and the child's environment stripped of every other credential. Its output is returned, capped in size, and the command is stopped at a timeout.

**It never widens authority**, because it adds no decision of its own:

- Every call reads and verifies the chain and its log proof again. Nothing is cached, so an expired, replaced or unlogged warrant stops working at the next call.
- There is no tool that issues or delegates a warrant, and none that returns credentials. The session credentials a command receives are the warrant's (short-lived, bounded by the session policy compiled from the warrant, and recorded with its identifier), never the broker's. A command that prints them gives away nothing the warrant did not already allow, and anything done with them is reconciled like any other action of that session.
- An operator may restrict `remit_run` to named programs (`--allow aws`), for a narrower surface than the warrant alone.

**No new dependencies** (ADR 0002): the protocol is JSON-RPC 2.0, one message per line, written directly on `serde_json`, which Remit already uses; tokio gains its `process` feature for the timeout.

**The plugin** (`integrations/claude-plugin/`) packages the server for Claude Code and the Claude Agent SDK: a manifest, the server's launch configuration, a skill that explains working under a warrant, and a hook that stops the agent from calling a cloud command-line tool (`aws`, `az`, `gcloud`) directly, so that it uses `remit_run`.
The hook is a guide rail, not the boundary: an agent that disguised a command could get past it.
The boundary is that the agent holds no cloud credentials at all; only the broker does, and only for a warrant.

## Consequences

- An agent builder installs one plugin, or points any MCP client at `remit mcp`, and the agent's cloud access is warranted, logged and reconcilable without wrapping every command by hand.
- The server's attack surface is the three tools; each is the existing Remit path, tested as the CLI is.
- AWS only today, like the broker; the tools are cloud-neutral in shape, so the Azure and Google Cloud brokers (to be designed) fit behind the same three tools.

## What would change it

An MCP revision that changes how tools are called, a framework that cannot run a local process (which would need the server over HTTP, with its own authentication), or evidence that agents need to request new warrants mid-task, which would add a tool that asks a person rather than one that grants.
