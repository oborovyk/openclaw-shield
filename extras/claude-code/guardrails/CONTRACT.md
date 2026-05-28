# Guardrail contract

A guardrail is an executable file in `core/guardrails/` that implements a stable I/O contract so it can be invoked from any provider's hook system, a git pre-commit, or CI.

## Invocation modes

Every guardrail MUST support at least these flags:

| Flag | Behaviour |
| --- | --- |
| `--file <path>` | Scan a single file. |
| `--dir <path>` | Scan all files under a directory (respecting `.gitignore`). |
| `--diff <ref>` | Scan the diff between `ref` and `HEAD`. |
| `--staged` | Scan currently-staged changes. |
| `--stdin` | Read JSON request from stdin (see below). |

## JSON I/O (stdin mode)

**Request (stdin):**

```json
{
  "kind": "file" | "command" | "tool-output",
  "content": "...",
  "context": {
    "provider": "claude-code" | "codex-cli" | "cli",
    "trigger": "pre-tool-use" | "post-tool-use" | "pre-commit",
    "tool": "Write" | "Edit" | "Bash" | null,
    "path": "src/foo.ts"
  }
}
```

**Response (stdout):**

```json
{
  "verdict": "allow" | "warn" | "block",
  "reason": "Detected AWS access key in line 42",
  "matches": [
    {"line": 42, "column": 10, "pattern": "aws-access-key", "snippet": "AKIA…"}
  ]
}
```

## Exit codes

- `0` — allow (no findings, or findings below warn threshold).
- `1` — warn (findings present but non-blocking; caller may surface to user).
- `2` — block (caller MUST refuse the action).

Stable exit codes let callers wire the guardrail into hook systems that only inspect exit status (e.g. git `pre-commit`).

## Ignore file

All guardrails MUST honour a `.openclawignore` file at the repo root (same syntax as `.gitignore`). Patterns with `/` match the full relative path; patterns without match the basename.

## Side effects

Guardrails MUST be read-only. They never write files, never mutate the index, never call out to the network unless the guardrail's purpose explicitly requires it (and that fact is documented in its `--help`).
