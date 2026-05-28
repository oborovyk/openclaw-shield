# openclaw-os

Provider-neutral security guardrails and reusable skills for coding-agent CLIs (Claude Code, ChatGPT/Codex CLI, Cursor, …).

Inspired by [silverblock-claude-os](https://github.com/silverblock/silverblock-claude-os), but redesigned around two abstractions that don't depend on any single provider:

- **Guardrails** — executable security checks (secret scan, prompt-injection scan, destructive-command scan, …) with a stable CLI + JSON contract. Wire them into Claude Code hooks, Codex CLI hooks, pre-commit, or CI — same binary, every time.
- **Skills** — provider-neutral instruction bundles (`skill.yaml` + `prompt.md`). Adapters lower them to each provider's native format (Claude Code `SKILL.md`, Codex CLI `AGENTS.md` snippets, …).

> **Status: usable for Claude Code.** All five guardrails are ported and the Claude Code adapter installs them into `~/.claude/settings.json` end-to-end. Codex CLI and other-provider adapters are still TODO. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design.

## Try it

```bash
cd ~/development/openclaw-os
./openclaw.sh install        # copies guardrails to ~/.openclaw/, wires hooks into ~/.claude/settings.json
./openclaw.sh list           # show installed guardrails
./openclaw.sh scan secret --staged
./openclaw.sh scan injection --dir .
./openclaw.sh uninstall      # reverse — leaves any non-openclaw hooks untouched
```

After `install`, restart Claude Code so it picks up the new hooks. From then on:
- `git commit ...` issued by Claude triggers secret-scan + prompt-injection-scan; non-zero exit blocks the commit.
- Every `Bash` tool call runs through destruction-scan; `rm -rf /` etc. blocked with exit 2.
- Every `Read` runs through read-injection-scanner; warns on injection patterns in agent-readable files.
- Every `Bash` output is scanned for leaked secrets and the model is warned not to repeat them.

The installer is idempotent and preserves any pre-existing entries in `~/.claude/settings.json`.

## Layout

```
openclaw-os/
├── openclaw.sh            # CLI entrypoint (install/doctor/sync/scan)            [TODO]
├── core/                  # PROVIDER-NEUTRAL — single source of truth
│   ├── guardrails/        # Python executables; CLI + JSON contract              [TODO]
│   ├── skills/            # <name>/skill.yaml + prompt.md                        [TODO]
│   └── instructions/      # global.md → rendered as CLAUDE.md / AGENTS.md / …    [TODO]
├── adapters/
│   ├── claude-code/       # marketplace + plugin shell exists; renderer [TODO]
│   └── codex-cli/         # empty                                                [TODO]
└── docs/
    └── ARCHITECTURE.md
```

## Why this shape

Silverblock's harness is built entirely on Claude Code primitives — `SKILL.md`, `commands/`, `hooks.json`, `claude plugin install`. None of those exist in ChatGPT/Codex CLI, Cursor, Continue, etc. To support more than one provider we need a layer above those primitives.

Openclaw treats the **core** (guardrails + skills + instructions) as the source of truth and the **adapters** as compilers that target each provider's native format. Add a new provider by writing one adapter; every existing guardrail and skill comes along for free.

