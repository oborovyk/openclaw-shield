# `@openclaw-os/security` — OpenClaw plugin

Runtime security guardrails for [OpenClaw](https://github.com/openclaw/openclaw). Ports the five scanners that live in [`../../core/guardrails/`](../../core/guardrails/) (Python) to a single TypeScript plugin that registers into OpenClaw's hook system.

## What it protects

| Hook | Guardrail | Behavior |
| --- | --- | --- |
| `inbound_claim` | Secret scan on inbound message text (every channel, including Telegram) | Warn + optional redaction before LLM sees the text |
| `inbound_claim` | Prompt-injection scan on inbound message text | Warn-only by default (chat-text false-positive risk); opt-in `blockOnInjection: true` to actively reject |
| `before_tool_call` | Destruction-rule scan against shell-like tool commands | **Block** with `{ block: true, blockReason: ... }` |
| `before_tool_call` | Secret scan on every string param value | **Block** (refuses to send credentials to a tool) |
| `after_tool_call` | Secret scan on shell-like tool output | Log a masked warning so the model is warned not to echo |
| `after_tool_call` | Prompt-injection scan on file/url-read tool results | Log a warning (indirect injection alert) |

Pattern packs are pure TypeScript ports of `core/guardrails/secret-scan.py`, `prompt-injection-scan.py`, and `destruction-scan.py` — no subprocess, no Python at runtime.

## Install (workspace-local, for development)

From the OpenClaw checkout:

```bash
# 1. Symlink this adapter into OpenClaw's pnpm workspace
cd /Users/oborovyk/development/ai/openclaw
ln -s /Users/oborovyk/development/openclaw-os/adapters/openclaw extensions/openclaw-os

# 2. Tell pnpm-workspace about it (or rely on extensions/* glob)
grep -q "extensions/\*" pnpm-workspace.yaml || echo '  - "extensions/*"' >> pnpm-workspace.yaml

# 3. Install + restart
pnpm install
pnpm dev          # or however you start the gateway
```

Once OpenClaw boots, look for `[openclaw-os] …` lines in stderr — that's the plugin announcing findings.

## Configuration

In your OpenClaw config (e.g. `config/openclaw.yaml`), under `plugins.entries`:

```yaml
plugins:
  entries:
    openclaw-os:
      inboundClaim:
        scanSecrets: true
        scanInjection: true
        redactSecrets: true
        blockOnInjection: false   # set true to hard-reject inbound prompt-injection
      beforeToolCall:
        destruction: true
        scanParamSecrets: true
      afterToolCall:
        scanReadResultsForInjection: true
        scanShellOutputForSecrets: true
      verboseLogging: false
```

All flags default to safe-on / block-on values except `inboundClaim.blockOnInjection` (opt-in).

## Coverage

- ✅ Every channel that delivers through `inbound_claim` (Telegram, WhatsApp, Slack, Discord, Signal, iMessage, …) is covered uniformly. Telegram isn't special.
- ✅ Every tool execution flows through `before_tool_call` → covered.
- ⚠️ Voice transcripts: covered (transcript text → `inbound_claim`). Raw audio: not scanned (different problem).
- ⚠️ Canvas / UI-direct events that bypass `inbound_claim`: not covered.

## TODO

- Unit tests for each pattern pack (mirror the Python `*_test.py` if present).
- Move pattern packs to `core/patterns/` so future TS adapters can share them without duplication.
- `before_prompt_build` hook to scan the assembled prompt for secrets pulled in via memory/skills.
