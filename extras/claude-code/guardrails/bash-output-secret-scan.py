#!/usr/bin/env python3
"""bash-output-secret-scan.py — PostToolUse hook on Bash.

Scans stdout + stderr from Bash tool calls for token-shaped strings. If any
match a known credential pattern, injects an `additionalContext` warning
into Claude's context telling it to mask the value before reproducing it.

Does NOT modify the tool output and does NOT block the tool. Purely advisory.

Why this exists:
A grep over ~/.env-like files, an `env` dump, a `curl -v` showing
Authorization headers, or just `cat ~/.zshenv` can spill credentials into
conversation context. From there they enter transcripts, may be summarised
back to the user, and become part of any follow-up the model does. This
hook raises visibility so Claude masks the value rather than echoing it.

Limits:
- Won't catch arbitrary opaque tokens (random base64). Only well-
  known provider formats and the common `KEY=VALUE` assignment pattern.
- Reactive — Claude has already read the output by the time this fires.
  The warning helps the model self-correct on subsequent turns.

Keep PATTERNS in sync with scripts/secret-scan.py.
"""
import json
import re
import sys

PATTERNS = [
    (re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'), "AWS access key"),
    (re.compile(r'\b(?:ghp_|gho_|ghu_|ghs_|github_pat_)[A-Za-z0-9_]{30,}'), "GitHub token"),
    (re.compile(r'\bglpat-[A-Za-z0-9_-]{20,}'), "GitLab PAT"),
    (re.compile(r'\bsk-ant-api\d{2}-[A-Za-z0-9_-]{40,}'), "Anthropic API key"),
    (re.compile(r'\bsk-[A-Za-z0-9_-]{30,}\b'), "OpenAI key"),
    (re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{10,}'), "Slack token"),
    (re.compile(r'\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}'), "Stripe key"),
    (re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'), "private key block"),
    # Generic KEY=VALUE / KEY: VALUE assignment — broader, lower confidence
    (re.compile(
        r'(?i)(?:export\s+)?\b\w*(?:token|secret|password|api[_-]?key|auth)\b\s*[:=]\s*["\']?[A-Za-z0-9/_\-+=.]{16,}["\']?'
    ), "credential assignment"),
]

try:
    data = json.loads(sys.stdin.read())
except Exception:
    sys.exit(0)

if data.get("tool_name") != "Bash":
    sys.exit(0)

resp = data.get("tool_response") or {}
content = (resp.get("stdout") or "") + "\n" + (resp.get("stderr") or "")
if not content.strip():
    sys.exit(0)

hits = set()
for pat, name in PATTERNS:
    if pat.search(content):
        hits.add(name)

if not hits:
    sys.exit(0)

cmd = (data.get("tool_input") or {}).get("command", "")
cmd_short = cmd[:80] + ("…" if len(cmd) > 80 else "")
msg = (
    f"⚠ BASH OUTPUT MAY CONTAIN A SECRET — detected pattern(s): "
    f"{', '.join(sorted(hits))}.\n"
    f"Command: `{cmd_short}`\n"
    f"DO NOT echo, repeat, summarise, or paste the full value back to the user. "
    f"If you must reference it, mask: show only the prefix + last 4 chars "
    f"(e.g. `glpat-…2Mg8`). If the leak was unintentional, alert the user to "
    f"rotate the token immediately."
)
print(json.dumps({
    "hookSpecificOutput": {
        "hookEventName": "PostToolUse",
        "additionalContext": msg,
    }
}))
