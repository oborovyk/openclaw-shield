# openclaw-os

Runtime security guardrails for [OpenClaw](https://github.com/openclaw/openclaw) — secret scan, prompt-injection scan, destruction guard, read-injection scan, bash-output secret scan, AES-encrypted secret cache — wired into OpenClaw's `inbound_claim`, `before_dispatch`, `before_tool_call`, and `after_tool_call` hooks.

This repo *is* the `@openclaw-os/security` OpenClaw plugin. Install it with one OpenClaw CLI command — works on Docker, nix, npm-global, source builds, anywhere `openclaw` runs.

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

One command, any OpenClaw deployment (Docker / nix / npm-global / source):

```bash
openclaw plugins install git:github.com/Silverblock-Finance/openclaw-os
openclaw plugins enable openclaw-os    # if not auto-enabled
```

OpenClaw resolves the plugin via your existing git credentials (gh auth, SSH key, or credential helper — same as `git clone`). The plugin lands in the right place for your deployment shape automatically.

Then add the config block to your openclaw runtime config, under `plugins.entries`:

```yaml
plugins:
  entries:
    openclaw-os:
      inboundClaim:    { scanSecrets: true, scanInjection: true, redactSecrets: true, blockOnInjection: false }
      beforeToolCall:  { destruction: true, scanParamSecrets: true }
      afterToolCall:   { scanReadResultsForInjection: true, scanShellOutputForSecrets: true }
```

Restart openclaw. Look for `[openclaw-os] …` lines in stderr to see findings.

### Pin to a tag or commit

```bash
openclaw plugins install git:github.com/Silverblock-Finance/openclaw-os@v0.1.0
openclaw plugins install git:github.com/Silverblock-Finance/openclaw-os@<commit-sha>
```

### Update

```bash
openclaw plugins update openclaw-os
```

### Disable (keep installed, stop running)

```bash
openclaw plugins disable openclaw-os
```

### Uninstall

```bash
openclaw plugins uninstall openclaw-os
```

Add `--dry-run` to see what either disable or uninstall will do without applying. Add `--keep-files` to uninstall to leave the plugin checkout on disk.

> Nix users: `OPENCLAW_NIX_MODE=1` makes `plugins install/update/uninstall/enable/disable` no-ops. Install via the [`nix-openclaw`](https://github.com/openclaw/nix-openclaw) source instead.

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
npm install           # vitest only; openclaw + plugin-sdk are optional peers
npm test              # 59 tests across patterns, cache, config, hooks
```

CI runs on push and PR to `main` via [.github/workflows/ci.yml](.github/workflows/ci.yml).

## Contributing / source builds

The repo ships an [install.sh](install.sh) for developers who run OpenClaw from a source checkout and want to drop this plugin into `extensions/`. End users on Docker / nix / npm-global don't need it — `openclaw plugins install` is the right path.

See [docs/OPENCLAW-PLUGIN.md](docs/OPENCLAW-PLUGIN.md) and [CLAUDE.md](CLAUDE.md) for the source-build flow and contributor notes.

## Layout

```
openclaw-os/
├── openclaw.plugin.json            ← OpenClaw plugin manifest (id, kind, configSchema)
├── package.json                    ← @openclaw-os/security
├── tsconfig.json                   ← self-contained
├── vitest.config.ts
├── index.ts                        ← definePluginEntry + 4 registerHook calls
├── install.sh                      ← contributor convenience for source builds
├── src/
│   ├── config.ts
│   ├── secret-cache.ts             ← AES-encrypted op:// resolver
│   ├── patterns/                   ← regex packs
│   ├── hooks/                      ← inbound-claim, before-dispatch, before-tool-call, after-tool-call
│   └── **/*.test.ts                ← 9 test files, 59 tests
├── docs/
│   └── OPENCLAW-PLUGIN.md          ← plugin reference + contributor install
├── CLAUDE.md                       ← agent-facing repo notes
└── .github/workflows/ci.yml
```
