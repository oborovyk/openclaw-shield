# CLAUDE.md

Agent-facing notes for working in this repo. For end-user / install docs, see [README.md](README.md) and [docs/OPENCLAW-PLUGIN.md](docs/OPENCLAW-PLUGIN.md).

## What this repo is

`@openclaw-os/security` — a single OpenClaw plugin that registers four runtime hooks (`inbound_claim`, `before_dispatch`, `before_tool_call`, `after_tool_call`) and applies regex-based security guardrails against the events that flow through them.

Designed to be symlinked into `openclaw/extensions/openclaw-os/` and auto-loaded by openclaw's pnpm-workspace + plugin loader. Works standalone for development and tests; the openclaw monorepo provides the `openclaw` and `@openclaw/plugin-sdk` peer dependencies at runtime via workspace resolution.

## Conventions

- **Pure TypeScript, in-process.** No subprocess calls, no Python at runtime. Pattern packs are TS modules; the secret cache uses Node's `crypto`.
- **`import type` from openclaw only.** Real `import` statements would force the openclaw workspace to be resolvable in standalone mode and break the test/CI flow. Stick to type-only imports for `PluginHook*` and friends.
- **Hooks must be pure observation OR return a typed result.** Mutating event objects in place is fragile and silently no-ops in several cases (see "Trap" below). If the contract permits a rewrite, return it; if it doesn't, treat the event as read-only.
- **Pattern arrays carry `label` + `regex` (+ `reason` for destruction).** Adding a new pattern means appending to the array; no central registry.
- **One pattern pack per concern**, one hook handler per openclaw hook. Don't multiplex.
- **Always log security findings.** They're low-volume and high-value; `console.warn("[openclaw-os] …")` until the host exposes a structured logger we can adopt.

## Trap that bit us once

The event passed to `inbound_claim` is a **copy** of the host's `hookContext` (`openclaw/src/hooks/message-hook-mappers.ts:319`). Mutating `event.bodyForAgent` from the handler does NOT change what the agent eventually sees. The original code did this and was silently a no-op for weeks.

The fix lives in `src/hooks/before-dispatch.ts`: `before_dispatch` has a result type `{ handled: false, text }` that the dispatcher actually reads back (`openclaw/src/auto-reply/reply/dispatch-from-config.ts:1886`). Any future rewrite-style behavior belongs there, not in `inbound_claim`.

Lesson: before writing a hook that mutates state, search the openclaw source for where the field is *read* after the hook fires.

## Project layout

```
index.ts                      definePluginEntry + 4 registerHook calls
src/config.ts                 schema → resolved config; defaults
src/secret-cache.ts           AES-encrypted op:// resolver
src/patterns/
  secret-patterns.ts          24 regexes (AWS / GitHub / OpenAI / …)
  injection-patterns.ts       35 regexes (DAN, role manipulation, …)
  destruction-rules.ts        11 rules (rm -rf /, force-push, DROP DATABASE, …)
src/hooks/
  inbound-claim.ts            warn / opt-in block
  before-dispatch.ts          rewrites body with redacted secrets (the only mutating hook)
  before-tool-call.ts         block destructive cmds + secrets-in-params
  after-tool-call.ts          warn on shell-output secrets, read-output injection
src/**/*.test.ts              9 files, 59 tests; vitest
```

## Commands

```bash
npm install     # vitest only; openclaw + plugin-sdk are optional peers
npm test        # vitest run, ~24s on a dev machine (op-read warmup), <1s in CI
npm run test:watch
```

## Editing a pattern pack

1. Append to the array in `src/patterns/<pack>.ts`.
2. Add a test case in the sibling `*.test.ts` covering at least one positive + one near-miss negative.
3. `npm test`.

Patterns are case-insensitive (`/i`) and non-global. Don't add a global flag — `scanSecrets` / `scanInjection` use `.match()` which retains state across calls if the regex is global.

## Adding a hook

1. Write `src/hooks/<name>.ts` exporting a `make<Name>Handler(config, log)` factory.
2. Register it in `index.ts` via `api.registerHook("<event_name>", make<Name>Handler(config, log), { name: "openclaw-os/<name>" })`.
3. Update `openclaw.plugin.json` `configSchema` if the hook has new toggles.
4. Update `src/config.ts` `GuardrailsConfig` + `DEFAULT_CONFIG`.
5. Add a test in `src/hooks/<name>.test.ts` using the existing mocked-event pattern (declare a local `Event` type, no openclaw-type imports).
6. Update [README.md](README.md) and [docs/OPENCLAW-PLUGIN.md](docs/OPENCLAW-PLUGIN.md) "What it protects" tables.

## Reference

- OpenClaw source (for spelunking): https://github.com/openclaw/openclaw — `git clone https://github.com/openclaw/openclaw.git ~/src/openclaw` is a convenient local checkout
- Hook type definitions: `openclaw/src/plugins/hook-types.ts`
- Plugin entry helper: `openclaw/packages/plugin-sdk/src/plugin-entry.ts`
- Memory-core extension (good real-world example of `definePluginEntry`): `openclaw/extensions/memory-core/`

## Out of scope

- **Static code-scan / OpenGrep rules** — openclaw already has `security/opengrep/` for that.
- **Claude Code / Codex CLI / Cursor support** — those have separate harnesses (e.g. silverblock-claude-os). This repo is OpenClaw-only.
- **Voice / canvas / non-`inbound_claim` channels** — call out as a coverage gap; don't try to scan raw audio bytes.
