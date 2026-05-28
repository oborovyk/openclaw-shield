# Skill contract

A skill is a provider-neutral instruction bundle. It lives at:

```
core/skills/<skill-name>/
├── skill.yaml          # required — manifest
├── prompt.md           # required — the instruction body
└── references/         # optional — supporting files referenced from prompt.md
```

## `skill.yaml`

```yaml
# Required
name: functional-review
description: Review a feature area for real bugs and small UX wins.
version: 0.1.0

# Required — one of: skill | command | guardrail-doc
# - skill: long-lived, trigger-based instructions (Claude Code SKILL.md, Codex AGENTS.md snippet)
# - command: short slash-command (Claude Code commands/, Codex prompt file)
# - guardrail-doc: human-readable doc for a guardrail living in core/guardrails/
kind: skill

# Required — which adapters should emit this skill. Use ["any"] for all.
providers: [claude-code, codex-cli]

# Optional — discovery hints. Adapters use these to populate native trigger fields.
triggers:
  - keyword: "functional review"
  - keyword: "find bugs in"
  - phrase:  "QA this feature"

# Optional — files under references/ to ship alongside.
references:
  - reference-mvp-wallet.md

# Optional — tools the skill needs; adapters may use this to gate or warn.
required_tools: [Read, Grep, Glob]
```

## `prompt.md`

Plain Markdown. References to bundled files use `${SKILL_ROOT}/references/...` — adapters substitute this with the provider-specific path at render time (e.g. `${CLAUDE_PLUGIN_ROOT}/skills/<name>/references/...` for Claude Code).

## Adapter rendering

| Provider | Lowered form |
| --- | --- |
| `claude-code` | `~/.claude/plugins/openclaw/skills/<name>/SKILL.md` with YAML frontmatter (`name`, `description`); `prompt.md` body inlined; `references/` copied verbatim. |
| `codex-cli` | Snippet appended to `~/.codex/AGENTS.md`; full prompt copied to `~/.codex/prompts/<name>.md`. |

## Versioning

`version` follows semver. Adapters MAY write a `.openclaw-version` sidecar so `openclaw sync` can detect drift between core and what's installed.
