# openclaw-os

Runtime security guardrails for [OpenClaw](https://github.com/openclaw/openclaw) — secret scan, prompt-injection scan, destruction guard, read-injection scan, bash-output secret scan, AES-encrypted secret cache — wired into OpenClaw's `inbound_claim`, `before_dispatch`, `before_tool_call`, and `after_tool_call` hooks.

This repo *is* the `@openclaw-os/security` OpenClaw plugin. Drop it into the `extensions/` folder of an OpenClaw checkout and every channel (Telegram, WhatsApp, Slack, Discord, …) starts getting scanned automatically.

## What it protects

| OpenClaw hook | Guardrail | Behavior |
| --- | --- | --- |
| `inbound_claim` | Secret scan on inbound channel text | Log (audit trail) |
| `inbound_claim` | Prompt-injection scan on inbound text | Log + opt-in hard-block via `blockOnInjection: true` |
| `before_dispatch` | Secret redaction | Rewrites the body the agent sees so credentials are masked (`first-4…last-4`) |
| `before_tool_call` | Destruction rules vs. shell-tool commands (`bash`, `exec`) | **Block** with `{ block: true, blockReason }` |
| `before_tool_call` | Secret scan on every string param | **Block** (refuses to send credentials to a tool) |
| `after_tool_call` | Secret scan on shell-tool output | Log (masked) so the model is warned not to echo |
| `after_tool_call` | Injection scan on file/url-read tool output | Log (indirect-injection alert) |

Coverage is channel-agnostic — every Telegram, WhatsApp, Slack, Discord, etc. message that openclaw claims runs through `inbound_claim`.

## Install

### One-liner (recommended)

From your OpenClaw repo root. The repo is private, so the easiest auth path is `gh` (most contributors already have it logged in):

```bash
gh api repos/Silverblock-Finance/openclaw-os/contents/install.sh -H 'Accept: application/vnd.github.raw' | bash
```

Or with `curl` + a GitHub PAT:

```bash
curl -fsSL -H "Authorization: Bearer $GH_TOKEN" \
  https://raw.githubusercontent.com/Silverblock-Finance/openclaw-os/main/install.sh | bash
```

Either form will clone the plugin into `extensions/openclaw-os/`, add `extensions/*` to `pnpm-workspace.yaml` if needed, and print next steps. Override the target with `OPENCLAW_DIR=/path/to/openclaw`.

### Manual

```bash
cd /path/to/openclaw
git clone https://github.com/Silverblock-Finance/openclaw-os.git extensions/openclaw-os
grep -q "extensions/\*" pnpm-workspace.yaml || echo '  - "extensions/*"' >> pnpm-workspace.yaml
pnpm install
pnpm dev   # or however you start the gateway
```

Prefer to keep the plugin in a separate working tree? Clone elsewhere and symlink:

```bash
git clone https://github.com/Silverblock-Finance/openclaw-os.git ~/src/openclaw-os
ln -s ~/src/openclaw-os /path/to/openclaw/extensions/openclaw-os
```

To track upstream:

```bash
cd /path/to/openclaw/extensions/openclaw-os  # or wherever you cloned
git pull
cd -; pnpm install   # picks up any new deps
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

## Secret cache helper

`src/secret-cache.ts` exports `secret(opPath, { envFallback })` for any plugin code that needs to resolve a 1Password secret without Touch-ID-prompting the user on every call. AES-256-CBC encrypted at-rest under `$TMPDIR/.openclaw-os-cache.<uid>/`, 3h default TTL, openssl-compatible file format.

```ts
import { secret } from "@openclaw-os/security/src/secret-cache.js";

const token = await secret("op://Employee/openclaw-os/github_token", {
  envFallback: "GITHUB_TOKEN",
});
```

Env knobs: `OPENCLAW_OS_SECRET_TTL=<seconds>`, `OPENCLAW_OS_NO_CACHE=1`. See [src/secret-cache.ts](src/secret-cache.ts) for full options.

## Tests + CI

```bash
npm install           # installs vitest; openclaw + plugin-sdk are optional peers
npm test              # 59 tests across patterns, cache, config, hooks
```

CI runs on push and PR to `main` via [.github/workflows/ci.yml](.github/workflows/ci.yml).

## Layout

```
openclaw-os/
├── openclaw.plugin.json            ← OpenClaw plugin manifest (id, kind, configSchema)
├── package.json                    ← @openclaw-os/security
├── tsconfig.json                   ← self-contained; works standalone + inside openclaw
├── vitest.config.ts
├── index.ts                        ← definePluginEntry + 4 registerHook calls
├── src/
│   ├── config.ts                   ← schema → resolved config
│   ├── secret-cache.ts             ← AES-encrypted op:// resolver
│   ├── patterns/                   ← regex packs
│   │   ├── secret-patterns.ts
│   │   ├── injection-patterns.ts
│   │   └── destruction-rules.ts
│   ├── hooks/
│   │   ├── inbound-claim.ts        ← warn / opt-in block
│   │   ├── before-dispatch.ts      ← rewrites body with redacted secrets
│   │   ├── before-tool-call.ts     ← block destructive cmds / secrets-in-params
│   │   └── after-tool-call.ts     ← warn on shell-output secrets, read-output injection
│   └── **/*.test.ts                ← 9 test files, 59 tests
├── docs/
│   └── OPENCLAW-PLUGIN.md          ← detailed plugin docs
├── CLAUDE.md                       ← agent-facing repo notes
└── .github/workflows/ci.yml
```
