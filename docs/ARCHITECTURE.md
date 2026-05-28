# openclaw-os architecture

openclaw-os is a **provider-neutral toolkit** for shipping security guardrails and reusable skills to coding-agent CLIs (Claude Code, ChatGPT/Codex CLI, Cursor, etc.).

The design separates **what** (guardrails, skills, instructions — authored once) from **how** (per-provider adapters that render to the target's native format).

## Layout

```
openclaw-os/
├── openclaw.sh                       # CLI entrypoint
├── core/                             # PROVIDER-NEUTRAL — source of truth
│   ├── guardrails/                   # Executable security checks
│   ├── skills/                       # Reusable agent skills (Markdown + manifest)
│   └── instructions/                 # Global instructions (drives CLAUDE.md / AGENTS.md / …)
├── adapters/                         # Per-provider renderers + installers
│   ├── claude-code/                  # Emits plugin marketplace, hooks.json, SKILL.md
│   └── codex-cli/                    # Emits AGENTS.md, prompt files
└── docs/
```

## Core abstractions

### 1. Guardrail

An executable security check. Provider-agnostic by design — it reads input on stdin or as a file, and prints a verdict.

**Contract:**

- Input: `--file <path>`, `--diff <ref>`, `--staged`, or JSON on stdin: `{"kind": "file"|"command"|"tool-output", "content": "...", "context": {...}}`
- Output: JSON on stdout: `{"verdict": "allow"|"warn"|"block", "reason": "...", "matches": [...]}`
- Exit code: `0` allow, `1` warn, `2` block.

This lets a single binary be wired into:
- Claude Code `PreToolUse` / `PostToolUse` hooks (via `hooks.json`)
- Codex CLI hooks (when available) or shell wrappers
- Plain `pre-commit` git hooks
- CI pipelines (`--diff origin/main`)

Initial guardrails to port from silverblock-claude-os:

| Guardrail | Purpose |
| --- | --- |
| `secret-scan` | AWS / OpenAI / Anthropic / GitHub / Stripe / Slack / Google / NPM keys; private-key headers; generic `api_key=` / `password=` patterns. |
| `prompt-injection-scan` | Instruction-override, role-manipulation, system-prompt-extraction, fake message boundaries, DAN/jailbreak patterns. |
| `read-injection-scan` | Warns on injection patterns in files the agent reads (PostToolUse:Read). |
| `bash-output-secret-scan` | Scans Bash tool output for leaked secrets before the agent sees them. |
| `destructive-command-scan` | Detects `rm -rf /`, `git push --force` to protected branches, etc., before tool execution. |

### 2. Skill

A reusable, provider-neutral instruction bundle. Stored as a directory:

```
core/skills/<skill-name>/
├── skill.yaml      # manifest: name, description, triggers, scope, providers
├── prompt.md       # the actual instructions (the body of CLAUDE Code's SKILL.md)
└── references/     # optional supporting files
```

**Manifest (`skill.yaml`):**

```yaml
name: functional-review
description: Review a feature area for real bugs and small UX wins.
version: 0.1.0
kind: skill                          # skill | command | guardrail-doc
providers: [claude-code, codex-cli]  # subset; "any" = all
triggers:
  - keyword: "functional review"
  - keyword: "find bugs in"
references:
  - reference-mvp-wallet.md
```

Adapters know how to lower this to the target format:
- `claude-code` → `SKILL.md` with frontmatter + `references/`
- `codex-cli` → an `AGENTS.md` snippet plus a prompt file under `~/.codex/prompts/`

### 3. Instructions

`core/instructions/global.md` is the single source of truth for global agent instructions (commit-message rules, security guardrails, company context, etc.). Adapters install it as:

- `~/.claude/CLAUDE.md` for Claude Code
- `~/.codex/AGENTS.md` for Codex CLI

with provider-specific sections gated via simple `<!-- provider:claude-code -->` … `<!-- /provider -->` markers.

## Adapters

Each adapter is a small directory with a manifest and an installer:

```
adapters/<provider>/
├── adapter.yaml          # which core kinds it consumes, output paths, install hooks
├── render.py             # core → provider-native files
└── README.md             # provider-specific setup notes
```

**Adapter contract (CLI verbs the top-level `openclaw.sh` calls):**

- `render --core <path> --out <path>` — produce provider-native artefacts in a staging dir.
- `install --staged <path>` — copy/symlink rendered artefacts into the user's home (`~/.claude/`, `~/.codex/`, …).
- `uninstall` — remove what was installed.
- `validate` — sanity check (target CLI installed, files in place, hooks resolvable).

## CLI

`openclaw.sh` is the user-facing CLI; it delegates to adapters and runs guardrails directly.

```bash
openclaw install                  # detect provider CLIs, install kit + adapters present
openclaw install --provider=claude-code,codex-cli
openclaw doctor                   # diagnose credentials, missing CLIs, broken hooks
openclaw sync                     # re-render and re-install from current core/
openclaw scan secret --staged     # invoke a guardrail directly
openclaw scan injection --file foo.md
```

## Build order

1. **Core guardrails** — port `secret-scan.py`, `prompt-injection-scan.py`, `read-injection-scanner.py`, `bash-output-secret-scan.py`, `destruction-scan.py` from silverblock-claude-os into `core/guardrails/`. They are already CLI-driven and project-agnostic — minimal changes.
2. **Guardrail JSON-on-stdin mode** — add the standardised JSON I/O so non-Claude harnesses can call them uniformly.
3. **`openclaw.sh scan`** — wire CLI verbs to the guardrails.
4. **`adapters/claude-code/`** — render guardrails as `hooks.json`, copy scripts to `~/.claude/scripts/`, install global `CLAUDE.md` from `core/instructions/global.md`.
5. **First skill ported to core** — e.g. `laptop-secrets-audit` (provider-neutral content already).
6. **`adapters/codex-cli/`** — emit `AGENTS.md` from instructions + each skill's `prompt.md`. No hook system in Codex CLI yet — wire guardrails as `pre-commit` git hooks instead.
7. **Validate end-to-end:** drop a fake AWS key in a repo, confirm Claude Code blocks the commit *and* a `git commit` from outside Claude blocks it via pre-commit.

## What we explicitly drop from silverblock-claude-os

- **Plugin marketplace as an architectural concept.** Only Claude Code understands it. In openclaw the marketplace is just one possible *output* of the `claude-code` adapter, not the source of truth.
- **`silverblock-claude-os.sh` 1Password coupling.** Keep the helper but make it pluggable — `openclaw secret <ref>` resolves from a chain of providers (1Password, `pass`, env vars, `.env`).
- **Daily-tooling skills tied to Google OAuth** (calendar, meeting-planner). Out of scope for a security/guardrails-focused harness; revisit later.
