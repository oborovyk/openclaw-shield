# Contributing to openclaw-shield

Thanks for the interest. The repo is small and the scope is narrow on purpose — runtime security guardrails for [OpenClaw](https://github.com/openclaw/openclaw). Read this before opening an issue or a PR.

## Scope

In scope:

- New credential / token patterns (Slack legacy tokens, regional AWS variants, Cohere, Mistral, …).
- New prompt-injection signatures.
- New destruction rules (catastrophic shell commands, dangerous SQL, dangerous infra-as-code verbs).
- Hook-handler improvements (better false-positive suppression, tighter detection logic).
- Bug fixes — anything where the runtime behavior contradicts what the docs claim.
- Performance — scans run synchronously on every message and tool call; latency matters.

Out of scope:

- Static analysis / linting (use OpenGrep in `openclaw/security/opengrep/`).
- Non-OpenClaw integrations (Claude Code, Codex CLI, Cursor — separate projects).
- General code-quality / refactor PRs without a behavior justification.

## How to propose a change

1. Open an issue first if the change isn't trivial. State the threat or false-positive you're addressing, with a minimal repro string if possible.
2. Fork, branch, code. Run `npm test` — all 64+ tests must pass.
3. **Every behavior change must ship with a test** in the matching `*.test.ts` file. Pattern-pack changes need at least one positive and one near-miss negative.
4. Keep the PR focused. One pattern family per PR, one hook-handler change per PR.
5. Update the relevant doc table:
   - New pattern in `src/patterns/secret-patterns.ts` → mention the credential type in README.md / OPENCLAW-PLUGIN.md "What it protects".
   - New hook → update the table in both docs and add a `make<Name>Handler` test file.

## Code conventions

- Pure TypeScript, in-process. No subprocess calls, no Python at runtime.
- `import type` from openclaw only (the openclaw monorepo is a workspace peer, not a hard dep — runtime tests must work without it).
- Hook handlers either mutate via a documented result type or are pure observation. Never mutate event objects expecting the host to re-read — see [CLAUDE.md](CLAUDE.md) "Trap that bit us once".
- Pattern packs return findings as data, not by throwing or `console.log`. Logging happens in the hook handler.
- Patterns are case-insensitive (`/i`) and non-global. Don't add the `g` flag.

## Reporting a bypass

If you've found a way to slip a credential past `before_tool_call`, an injection past `inbound_claim`, or a destructive command past `before_tool_call.destruction`, please follow [SECURITY.md](SECURITY.md) for private disclosure — don't open a public issue first.

## License

By contributing you agree your contribution is licensed under the same MIT license as the rest of the repo (see [LICENSE](LICENSE)).
