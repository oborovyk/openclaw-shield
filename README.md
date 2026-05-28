# openclaw-os

Runtime security guardrails for [OpenClaw](https://github.com/openclaw/openclaw) — secret scan, prompt-injection scan, destruction guard, read-injection scan, bash-output secret scan — wired into OpenClaw's `inbound_claim`, `before_tool_call`, and `after_tool_call` hooks.

This repo *is* the `@openclaw-os/security` OpenClaw plugin. Drop it into the `extensions/` folder of an OpenClaw checkout and every channel (Telegram, WhatsApp, Slack, Discord, …) starts getting scanned automatically.

## What it protects

| OpenClaw hook | Guardrail | Behavior |
| --- | --- | --- |
| `inbound_claim` | Secret scan on inbound channel text | Warn + redact before LLM sees it |
| `inbound_claim` | Prompt-injection scan on inbound text | Warn (opt-in hard-block via `blockOnInjection: true`) |
| `before_tool_call` | Destruction rules vs. shell-like tool commands | **Block** with `{ block: true, blockReason }` |
| `before_tool_call` | Secret scan on every string param | **Block** (refuses to send credentials to a tool) |
| `after_tool_call` | Secret scan on shell-tool output | Warn (masked) so the model is told not to echo |
| `after_tool_call` | Injection scan on file/url-read tool output | Warn (indirect-injection alert) |

Coverage is channel-agnostic — every Telegram, WhatsApp, Slack, Discord, etc. message that openclaw claims runs through `inbound_claim`.

## Install

From an OpenClaw checkout:

```bash
cd /path/to/openclaw
ln -s /Users/oborovyk/development/clients/openclaw-os extensions/openclaw-os
grep -q "extensions/\*" pnpm-workspace.yaml || echo '  - "extensions/*"' >> pnpm-workspace.yaml
pnpm install
pnpm dev   # or however you start the gateway
```

Then in your openclaw config:

```yaml
plugins:
  entries:
    openclaw-os:
      inboundClaim:    { scanSecrets: true, scanInjection: true, redactSecrets: true, blockOnInjection: false }
      beforeToolCall:  { destruction: true, scanParamSecrets: true }
      afterToolCall:   { scanReadResultsForInjection: true, scanShellOutputForSecrets: true }
```

Look for `[openclaw-os] …` lines in stderr to see findings. Full plugin docs: [docs/OPENCLAW-PLUGIN.md](docs/OPENCLAW-PLUGIN.md).

## Layout

```
openclaw-os/
├── openclaw.plugin.json        ← OpenClaw plugin manifest
├── package.json                ← @openclaw-os/security (workspace package)
├── tsconfig.json
├── index.ts                    ← definePluginEntry + registerHook calls
├── src/
│   ├── config.ts
│   ├── patterns/               ← regex packs (secret, injection, destruction)
│   └── hooks/                  ← inbound-claim, before-tool-call, after-tool-call
└── docs/
    └── OPENCLAW-PLUGIN.md
```
