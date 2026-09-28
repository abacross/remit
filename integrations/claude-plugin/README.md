# Remit plugin for Claude Code and the Claude Agent SDK

Your agent reaches the cloud only through a warrant a person signed (ADR 0009).

- **Three tools** from `remit mcp`: `remit_warrant` shows what the warrant allows, `remit_check` tests one action on one resource, and `remit_run` runs one cloud command with short-lived credentials stamped with the warrant, after checking that the warrant is valid now and proven logged.
- **A hook** (`remit hook pre-tool-use`) that refuses shell commands starting `aws`, `az`, `gcloud`, `gsutil` or `bq` directly, and tells the agent to use `remit_run`. It is a guide rail, not the boundary: the boundary is that the agent holds no cloud credentials at all.
- **A skill**, `working-under-a-warrant`, that tells the agent how to plan inside its grants and to stop and report when something is refused rather than look for another route.

## Before you install

1. `remit` on your `PATH`, and `remit init` and `remit task` for the rest of this list (docs/GETTING-STARTED.md).
2. A warrant chain for the agent, signed by a key you trust (`remit warrant issue`), logged and proven (`remit log append`, `remit log prove`) under a trust policy.
3. The role the broker assumes, whose trust policy requires a Remit warrant id as the session's source identity (`deploy/aws/role.yaml`), and credentials for the broker itself in the environment `remit` runs in. Keep them out of the agent's reach where you can: an agent that can read them can open sessions itself, which the reconciler reports but cannot prevent (THREAT-MODEL, known gap 3).

## Install

Claude Code: `claude --plugin-dir integrations/claude-plugin`, or add this repository as a plugin marketplace.
When the plugin is enabled, Claude Code asks for the warrant chain, the trusted root key, the role, the log's trust policy and the logged proof.

Claude Agent SDK:

```python
options = ClaudeAgentOptions(plugins=[{"type": "local", "path": "/path/to/remit/integrations/claude-plugin"}])
```

In the SDK, the plugin's options are read from `pluginConfigs` in the user's Claude settings (`~/.claude/settings.json`), under the plugin's id.

## Checked

- `claude plugin validate integrations/claude-plugin` passes.
- `cargo test -p remit-cli` parses the plugin's MCP server line and hook line with the real CLI, so they cannot drift apart.
- `examples/mcp/demo.sh` drives `remit mcp` over stdio without AWS.
- On 2026-09-27 a headless Claude Code session loaded the server and the hook: it read the warrant, was told `s3:DeleteObject` is not granted, had a direct `aws s3 ls` refused by the hook, and called `remit_run` instead, which reached the broker.
