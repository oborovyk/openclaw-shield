# `@openclaw-os/security` — OpenClaw plugin

Runtime security guardrails for [OpenClaw](https://github.com/openclaw/openclaw). Single TypeScript plugin, registers four hooks, pure in-process (no subprocess, no Python).

## What it protects

| Hook | Guardrail | Behavior |
| --- | --- | --- |
| `inbound_claim` | Secret scan on inbound message text (every channel) | Log finding |
| `inbound_claim` | Prompt-injection scan on inbound text | Log + opt-in hard-block (`blockOnInjection: true`) |
| `before_dispatch` | Secret redaction in dispatched body | Rewrites `text` so the agent sees `[openclaw-os redacted: AWS Access Key → AKIA…YQRE]` instead of the token |
| `before_tool_call` | Destruction-rule scan against canonical shell tools (`bash`, `exec`) | **Block** with `{ block: true, blockReason }` |
| `before_tool_call` | Secret scan on every string param value | **Block** (refuses to send credentials to a tool) |
| `after_tool_call` | Secret scan on shell-tool output | Log masked warning so the model is told not to echo |
| `after_tool_call` | Prompt-injection scan on file/url-read tool results | Log warning (indirect-injection alert) |

### Why inbound_claim and before_dispatch are split

`inbound_claim` fires first but its event is a *copy* of the host's `hookContext` (see openclaw `src/hooks/message-hook-mappers.ts:319`). Mutating `event.bodyForAgent` does NOT propagate back to the dispatcher — `inbound_claim` is therefore observation-only (log + optional `handled: true` hard block via reply).

Actual redaction lives in `before_dispatch`, whose result type `{ handled: false, text }` IS read back by the dispatcher (`src/auto-reply/reply/dispatch-from-config.ts:1886`).

## Install (workspace-local)

From the OpenClaw checkout:

```bash
# 1. Symlink this repo into OpenClaw's extensions/
cd /path/to/openclaw
ln -s /Users/oborovyk/development/clients/openclaw-os extensions/openclaw-os

# 2. Tell pnpm-workspace about extensions/* if not already declared
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
        redactSecrets: true       # applied in before_dispatch
        blockOnInjection: false   # set true to hard-reject inbound prompt-injection in inbound_claim
      beforeToolCall:
        destruction: true
        scanParamSecrets: true
      afterToolCall:
        scanReadResultsForInjection: true
        scanShellOutputForSecrets: true
      verboseLogging: false       # currently a no-op; reserved for future per-handler diagnostics
```

All flags default to safe-on / block-on values except `inboundClaim.blockOnInjection` (opt-in — chat-text false-positive risk is too high to block by default).

## Secret cache (`src/secret-cache.ts`)

Helper for any plugin code that needs to resolve a 1Password secret without prompting Touch ID on every call.

- Cache dir: `$TMPDIR/.openclaw-os-cache.<uid>/` (mode 0700)
- File format: openssl-compatible (`enc -aes-256-cbc -pbkdf2 -salt`) — files are inspectable from the shell with the per-user salt at `<cache>/.salt`
- Threat model: obfuscation against backup scanners, NOT real encryption against an attacker with read access to the home dir (identical model to silverblock-claude-os)
- TTL: 3h default; override via `OPENCLAW_OS_SECRET_TTL=<seconds>` or per-call `opts.ttl`
- Bypass: `OPENCLAW_OS_NO_CACHE=1` env or per-call `opts.noCache: true`
- Resolution chain: `op read <opPath>` → `opts.envFallback` env var → `null`

```ts
import { secret, clearSecretCache } from "../secret-cache.js";

const token = await secret("op://Employee/openclaw-os/github_token", {
  envFallback: "GITHUB_TOKEN",
});

// Wipe cache (next call re-fetches from op + writes new file under a new salt)
clearSecretCache();
```

## Coverage and gaps

- ✅ Every channel that delivers through `inbound_claim` (Telegram, WhatsApp, Slack, Discord, Signal, iMessage, …) is covered uniformly. Telegram isn't special.
- ✅ Every tool execution flows through `before_tool_call` → covered.
- ✅ Every dispatched agent prompt gets secret redaction via `before_dispatch`.
- ⚠️ Voice transcripts: covered (transcript text → `inbound_claim`). Raw audio: not scanned (different problem).
- ⚠️ Canvas / UI-direct events that bypass `inbound_claim`: not covered.
- ⚠️ Secrets pulled in via memory/skills *after* `before_dispatch` are not scanned. Future work: register `before_prompt_build` hook for late-binding redaction.

## Tests

```bash
npm install
npm test       # 59 tests across patterns, cache, config, hooks
```

See [../README.md](../README.md#tests--ci) for layout and CI details.

## Reference

- Hook types: `openclaw/src/plugins/hook-types.ts`, `openclaw/src/plugins/hook-message.types.ts`
- Plugin entry helper: `openclaw/packages/plugin-sdk/src/plugin-entry.ts`
- Dispatcher (where `before_dispatch.text` is read back): `openclaw/src/auto-reply/reply/dispatch-from-config.ts:1886`
- Canonical shell tools: `openclaw/src/agents/sessions/tools/bash.ts:287` (`bash`), `openclaw/src/agents/bash-tools.exec.ts:1276` (`exec`) — both use a `command` string param
