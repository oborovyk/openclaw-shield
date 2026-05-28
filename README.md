# openclaw-shield

[![CI](https://github.com/oborovyk/openclaw-shield/actions/workflows/ci.yml/badge.svg)](https://github.com/oborovyk/openclaw-shield/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![OpenClaw plugin](https://img.shields.io/badge/OpenClaw-plugin-blueviolet)](https://github.com/openclaw/openclaw)
[![Node.js](https://img.shields.io/badge/Node.js-22%2B-brightgreen)](https://nodejs.org/)
[![Tests](https://img.shields.io/badge/tests-101-brightgreen)](src)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](CONTRIBUTING.md)
[![Security policy](https://img.shields.io/badge/security-policy-informational)](SECURITY.md)

Runtime security guardrails for [OpenClaw](https://github.com/openclaw/openclaw) — secret scan, prompt-injection scan, destruction guard, read-injection scan, bash-output secret scan, AES-encrypted secret cache — wired into OpenClaw's `inbound_claim`, `before_dispatch`, `before_tool_call`, and `after_tool_call` hooks.

This repo *is* the `@openclaw-shield/security` OpenClaw plugin. Install it with one OpenClaw CLI command — works on Docker, nix, npm-global, source builds, anywhere `openclaw` runs.

## What it protects

| OpenClaw hook | Guardrail | Behavior |
| --- | --- | --- |
| `inbound_claim` | Secret scan on inbound channel text | Log (audit trail) |
| `inbound_claim` | Prompt-injection scan on inbound text | Log + opt-in hard-block via `blockOnInjection: true` |
| `before_dispatch` | Secret redaction | Rewrites the body the agent sees so credentials are masked (`first-4…last-4`) |
| `before_prompt_build` | Late-binding secret scan on the assembled prompt | Detect-and-instruct — appends a system-prompt refusal if a credential slipped in via memory / skills / prior turn (the hook can't rewrite the prompt, only append context) |
| `before_tool_call` | Destruction rules vs. shell-tool commands (`bash`, `exec`) | **Block** with `{ block: true, blockReason }` |
| `before_tool_call` | Secret scan on every string param | **Block** (refuses to send credentials to a tool) |
| `after_tool_call` | Secret scan on shell-tool output | Log (masked) so the model is warned not to echo |
| `after_tool_call` | Injection scan on file/url-read tool output | Log (indirect-injection alert) |

Coverage is channel-agnostic — every Telegram, WhatsApp, Slack, Discord, etc. message that openclaw claims runs through `inbound_claim`.

## Install

One command, any OpenClaw deployment (Docker / nix / npm-global / source):

```bash
openclaw plugins install git:github.com/oborovyk/openclaw-shield
openclaw plugins enable openclaw-shield    # if not auto-enabled
```

OpenClaw resolves the plugin via your existing git credentials (gh auth, SSH key, or credential helper — same as `git clone`). The plugin lands in the right place for your deployment shape automatically.

Then add the config block to your openclaw runtime config, under `plugins.entries`:

```yaml
plugins:
  entries:
    openclaw-shield:
      inboundClaim:       { scanSecrets: true, scanInjection: true, redactSecrets: true, blockOnInjection: false }
      beforePromptBuild:  { scanAssembledPrompt: true }
      beforeToolCall:     { destruction: true, scanParamSecrets: true }
      afterToolCall:   { scanReadResultsForInjection: true, scanShellOutputForSecrets: true }
```

Restart openclaw. Look for `[openclaw-shield] …` lines in stderr to see findings.

### Pin to a tag or commit

```bash
openclaw plugins install git:github.com/oborovyk/openclaw-shield@v0.1.0
openclaw plugins install git:github.com/oborovyk/openclaw-shield@<commit-sha>
```

### Update

```bash
openclaw plugins update openclaw-shield
```

### Disable (keep installed, stop running)

```bash
openclaw plugins disable openclaw-shield
```

### Uninstall

```bash
openclaw plugins uninstall openclaw-shield
```

Add `--dry-run` to see what either disable or uninstall will do without applying. Add `--keep-files` to uninstall to leave the plugin checkout on disk.

> Nix users: `OPENCLAW_NIX_MODE=1` makes `plugins install/update/uninstall/enable/disable` no-ops. Install via the [`nix-openclaw`](https://github.com/openclaw/nix-openclaw) source instead.

## Secret cache helper

`src/secret-cache.ts` exports `secret(ref, { envFallback })` for any plugin code that needs to resolve a secret-manager reference without re-prompting (Touch ID / keychain unlock / re-auth) on every call. AES-256-CBC encrypted at-rest under `$TMPDIR/.openclaw-shield-cache.<uid>/`, 3h default TTL, openssl-compatible file format.

**Supported reference shapes** (dispatch by URL prefix; see [src/resolvers.ts](src/resolvers.ts) to add a new manager):

| Prefix | Manager | Underlying CLI |
| --- | --- | --- |
| `op://<vault>/<item>/<field>` | 1Password | `op read` |
| `bws://<secret-id>` | Bitwarden Secrets Manager | `bws secret get` |
| `doppler://<project>/<config>/<key>` | Doppler | `doppler secrets get` |
| `infisical://<env>/<key>` | Infisical | `infisical secrets get` |
| `vault://<path>/<field>` | HashiCorp Vault | `vault kv get -field=` |
| `pass://<name>` | Unix password store | `pass show` |
| `keychain://<account>@<service>` | macOS Keychain | `security find-generic-password` |
| `aws-sm://<name>` | AWS Secrets Manager | `aws secretsmanager get-secret-value` |

```ts
import { secret } from "@openclaw-shield/security/src/secret-cache.js";

// Works for any of the 8 managers — dispatch is by URL prefix.
const token = await secret("op://<vault>/<item>/credential", { envFallback: "MY_TOKEN_ENV_VAR" });
const doppler = await secret("doppler://my-project/dev/STRIPE_KEY");
const vault   = await secret("vault://secret/path/api_key");
```

**Env knobs**:

- `OPENCLAW_SHIELD_SECRET_TTL=<seconds>` — override the 3h default.
- `OPENCLAW_SHIELD_NO_CACHE=1` — bypass the cache entirely.
- `OPENCLAW_SHIELD_CACHE_DIR=<path>` — override the cache directory (default `$TMPDIR/.openclaw-shield-cache.<uid>/`).

**Deployment notes**:

- **macOS**: works out of the box. `$TMPDIR` is per-user and persists across reboots; cache entries are TTL-pruned automatically.
- **Docker**: `/tmp` inside the container is ephemeral — the cache is rebuilt after every container restart. If you actually use `op read` (i.e. `op` is installed in the container), mount a volume and point the cache there:
  ```bash
  docker run \
    -v openclaw-shield-cache:/cache \
    -e OPENCLAW_SHIELD_CACHE_DIR=/cache \
    ...
  ```
  If you're injecting secrets via plain env vars (the common Docker pattern), the cache hardly matters — env-var reads are already cheap, and `op` typically isn't installed in the container anyway.

## Tests + CI

```bash
npm install           # vitest only; openclaw + plugin-sdk are optional peers
npm test              # 64 tests across patterns, cache, config, hooks
```

CI runs on push and PR to `main` via [.github/workflows/ci.yml](.github/workflows/ci.yml).

## Contributing / source builds

The repo ships an [install.sh](install.sh) for developers who run OpenClaw from a source checkout and want to drop this plugin into `extensions/`. End users on Docker / nix / npm-global don't need it — `openclaw plugins install` is the right path.

See [docs/OPENCLAW-PLUGIN.md](docs/OPENCLAW-PLUGIN.md) and [CLAUDE.md](CLAUDE.md) for the source-build flow and contributor notes.

## Layout

```
openclaw-shield/
├── openclaw.plugin.json            ← OpenClaw plugin manifest (id, kind, configSchema)
├── package.json                    ← @openclaw-shield/security
├── tsconfig.json                   ← self-contained
├── vitest.config.ts
├── index.ts                        ← definePluginEntry + 5 registerHook calls
├── install.sh                      ← contributor convenience for source builds
├── src/
│   ├── config.ts
│   ├── secret-cache.ts             ← AES-encrypted op:// resolver
│   ├── patterns/                   ← regex packs
│   ├── hooks/                      ← inbound-claim, before-dispatch, before-prompt-build, before-tool-call, after-tool-call
│   └── **/*.test.ts                ← 10 test files, 64 tests
├── docs/
│   └── OPENCLAW-PLUGIN.md          ← plugin reference + contributor install
├── CLAUDE.md                       ← agent-facing repo notes
└── .github/workflows/ci.yml
```

## License & contributing

MIT — see [LICENSE](LICENSE).

- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md) — scope, code conventions, how to propose pattern changes.
- Reporting a vulnerability: [SECURITY.md](SECURITY.md) — please disclose privately first.
