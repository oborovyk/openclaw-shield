#!/usr/bin/env bash
# extras/claude-code/install.sh — install openclaw-os guardrails into Claude Code.
#
# What this does:
#   1. Copies extras/claude-code/guardrails/*.py to ~/.openclaw/guardrails/
#   2. Merges PreToolUse/PostToolUse hook entries into ~/.claude/settings.json
#   3. Idempotent — safe to re-run on every git pull.
#
# Honours $CLAUDE_HOME (default ~/.claude) and $OPENCLAW_HOME (default ~/.openclaw)
# so the installer can be exercised against a temp directory in tests.
#
# Usage:
#   extras/claude-code/install.sh install     [CLAUDE_CODE_DIR]
#   extras/claude-code/install.sh uninstall

set -eo pipefail

CLAUDE_HOME="${CLAUDE_HOME:-$HOME/.claude}"
OPENCLAW_HOME="${OPENCLAW_HOME:-$HOME/.openclaw}"
SETTINGS_FILE="${CLAUDE_HOME}/settings.json"

# Stable markers so re-runs replace, not duplicate.
HOOK_TAG="openclaw-os"

guardrail_paths_json() {
  cat <<EOF
{
  "secret":         "${OPENCLAW_HOME}/guardrails/secret-scan.py",
  "injection":      "${OPENCLAW_HOME}/guardrails/prompt-injection-scan.py",
  "destruction":    "${OPENCLAW_HOME}/guardrails/destruction-scan.py",
  "read-injection": "${OPENCLAW_HOME}/guardrails/read-injection-scanner.py",
  "bash-output":    "${OPENCLAW_HOME}/guardrails/bash-output-secret-scan.py"
}
EOF
}

copy_guardrails() {
  local base_dir="$1"
  local src="${base_dir}/guardrails"
  mkdir -p "${OPENCLAW_HOME}/guardrails"
  cp "${src}"/*.py "${OPENCLAW_HOME}/guardrails/"
  chmod +x "${OPENCLAW_HOME}/guardrails/"*.py
  echo "✓ guardrails  → ${OPENCLAW_HOME}/guardrails/"
}

merge_hooks() {
  mkdir -p "${CLAUDE_HOME}"
  [ -f "${SETTINGS_FILE}" ] || echo '{}' > "${SETTINGS_FILE}"

  python3 - "$SETTINGS_FILE" "$OPENCLAW_HOME" "$HOOK_TAG" <<'PY'
import json, sys, os
settings_path, openclaw_home, tag = sys.argv[1:4]

with open(settings_path) as f:
    s = json.load(f)

guardrails = f"{openclaw_home}/guardrails"

# Pre-commit (Bash PreToolUse): only when the command is `git commit ...`
precommit_cmd = (
    'INPUT=$(cat); '
    'CMD=$(echo "$INPUT" | jq -r \'.tool_input.command // empty\' 2>/dev/null); '
    'echo "$CMD" | grep -qE \'(^|[[:space:];&|])[[:space:]]*git[[:space:]]+commit([[:space:]]|$)\' || exit 0; '
    f'[ -f "{guardrails}/secret-scan.py" ] && [ -f "{guardrails}/prompt-injection-scan.py" ] || '
    f'{{ echo "openclaw-os guardrails not found at {guardrails} — run openclaw install" >&2; exit 0; }}; '
    f'python3 "{guardrails}/secret-scan.py" --staged && '
    f'python3 "{guardrails}/prompt-injection-scan.py" --staged || '
    '{ echo "Commit blocked: secret or prompt-injection scan failed. Fix findings above and re-stage." >&2; exit 2; }'
)

new_hooks = {
    "PreToolUse": [
        {
            "matcher": "Bash",
            "_openclaw": tag,
            "hooks": [
                {
                    "type": "command",
                    "command": precommit_cmd,
                    "timeout": 30,
                    "statusMessage": "openclaw: scanning staged files for secrets and prompt injection",
                },
                {
                    "type": "command",
                    "command": f'[ -f {guardrails}/destruction-scan.py ] && python3 {guardrails}/destruction-scan.py || exit 0',
                    "timeout": 5,
                    "statusMessage": "openclaw: scanning for catastrophic shell commands",
                },
            ],
        }
    ],
    "PostToolUse": [
        {
            "matcher": "Read",
            "_openclaw": tag,
            "hooks": [{
                "type": "command",
                "command": f'[ -f {guardrails}/read-injection-scanner.py ] && python3 {guardrails}/read-injection-scanner.py || exit 0',
                "timeout": 10,
            }],
        },
        {
            "matcher": "Bash",
            "_openclaw": tag,
            "hooks": [{
                "type": "command",
                "command": f'[ -f {guardrails}/bash-output-secret-scan.py ] && python3 {guardrails}/bash-output-secret-scan.py || exit 0',
                "timeout": 10,
            }],
        },
    ],
}

# Merge: strip any prior openclaw-tagged entries, keep everything else, append ours.
hooks = s.setdefault("hooks", {})
for event, entries in new_hooks.items():
    existing = hooks.get(event, [])
    filtered = [e for e in existing if not (isinstance(e, dict) and e.get("_openclaw") == tag)]
    hooks[event] = filtered + entries

with open(settings_path, "w") as f:
    json.dump(s, f, indent=2)
    f.write("\n")
print(f"✓ hooks       → {settings_path}")
PY
}

uninstall_hooks() {
  [ -f "${SETTINGS_FILE}" ] || { echo "no settings.json at ${SETTINGS_FILE}"; return 0; }
  python3 - "$SETTINGS_FILE" "$HOOK_TAG" <<'PY'
import json, sys
path, tag = sys.argv[1:3]
with open(path) as f: s = json.load(f)
hooks = s.get("hooks", {})
removed = 0
for event in list(hooks.keys()):
    before = len(hooks[event])
    hooks[event] = [e for e in hooks[event] if not (isinstance(e, dict) and e.get("_openclaw") == tag)]
    removed += before - len(hooks[event])
    if not hooks[event]:
        del hooks[event]
if not hooks:
    s.pop("hooks", None)
with open(path, "w") as f:
    json.dump(s, f, indent=2); f.write("\n")
print(f"✓ removed {removed} openclaw hook entr{'y' if removed == 1 else 'ies'} from {path}")
PY
}

remove_guardrails() {
  if [ -d "${OPENCLAW_HOME}/guardrails" ]; then
    rm -rf "${OPENCLAW_HOME}/guardrails"
    echo "✓ removed ${OPENCLAW_HOME}/guardrails/"
  fi
  rmdir "${OPENCLAW_HOME}" 2>/dev/null || true
}

case "${1:-}" in
  install)
    base_dir="${2:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
    copy_guardrails "$base_dir"
    merge_hooks
    echo
    echo "openclaw-os installed for Claude Code."
    echo "Restart Claude Code (or open a new session) so the new hooks load."
    ;;
  uninstall)
    uninstall_hooks
    remove_guardrails
    ;;
  *)
    echo "usage: $0 {install|uninstall} [REPO_ROOT]" >&2
    exit 64
    ;;
esac
