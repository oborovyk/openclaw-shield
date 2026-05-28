#!/usr/bin/env python3
"""destruction-scan.py — PreToolUse hook on Bash.

Hard-blocks a curated set of catastrophic shell commands. Modelled on
aws-profile-guard (devops plugin): regex-scan the command string segmented
on shell separators, exit 2 with a message on match. Otherwise no-op.

Bypass: set ``OPENCLAW_ALLOW_DESTRUCTIVE=1`` in the shell that started Claude
Code. The variable is per-session — once the session ends, the guard is
back on. The author's note in the kit's CLAUDE.md says destructive
operations need explicit authorization in the current conversation; this
env var is the user telling the harness "I just authorized destruction
for this session", and the hook trusts that signal.

Scope (intentionally narrow):
  - Filesystem catastrophes:    ``rm -rf /``, ``rm -rf ~`` / ``$HOME``,
                                ``find / -delete``, ``chmod -R 777 /``
  - Block-device wipes:         ``dd of=/dev/sd*``/``/dev/disk*``/``/dev/nvme*``,
                                ``mkfs.* /dev/...``
  - Git history rewriters:      ``git push --force`` to ``main``/``master``
                                (any remote)
  - IaC tear-downs:             ``terraform destroy`` / ``tofu destroy``
                                without ``--target``
  - K8s namespace deletes:      ``kubectl delete ns/namespace ...``,
                                ``kubectl delete --all`` (no selector)
  - DB drops:                   ``DROP DATABASE``, ``DROP TABLE`` when
                                passed via ``psql -c`` / ``mysql -e`` /
                                inline HEREDOC

What this hook deliberately does NOT try to catch:
  - ``docker system prune -af``: contextually fine on a dev laptop.
  - ``helm uninstall``: routine on ephemeral envs.
  - ``rm -rf <relative-path>``: too many false positives, lets agents
    clean up build dirs and tmp scratch.
  - ``DELETE FROM ... (no WHERE)``: regex-parsing SQL inside shell quoting
    is unreliable; we'd rather miss than block legitimate seeds.

Decision protocol (Claude Code PreToolUse hook contract):
  - Exit 0 → allow the tool call
  - Exit 2 → block; stderr message is shown to the user

Stdlib only — runs as ``python3 ...`` per kit convention.
"""

from __future__ import annotations

import json
import os
import re
import sys

# Per-session bypass. Set in the shell that started Claude Code.
if os.environ.get("OPENCLAW_ALLOW_DESTRUCTIVE") == "1":
    sys.exit(0)

SEGMENT_SPLIT_RE = re.compile(r"(?:&&|\|\||;|\n)")

# Catastrophic-target paths: filesystem root, key system directories,
# the user's home (literal ~, $HOME, ${HOME}). The trailing lookahead is
# `(?=\s|$)` rather than `\b` because `/` and `~` are non-word chars and
# `\b` doesn't match between two non-word chars (e.g. `/` + end-of-string).
# Subpaths under these roots are also caught: `/usr/*`, `~/*`, `$HOME/*`.
_DANGEROUS_PATH = (
    r"(?:"
    r"/|/\*"                                      # /, /*
    r"|/(?:usr|etc|var|bin|sbin|boot|lib|opt|root|home"
    r"|System|Library|Applications)(?:/\*)?"      # /usr, /etc, /System, etc.
    r"|~(?:/\*)?"                                 # ~, ~/*
    r"|\$\{?HOME\}?(?:/\*)?"                      # $HOME, ${HOME}, $HOME/*
    r")"
)

# Each entry: (label, compiled-regex, why-this-is-blocked).
# Patterns are deliberately conservative — only the unambiguous catastrophes.
PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "rm -rf root / system-dir / home",
        re.compile(
            # Require `r` (recursive) somewhere — `-f` alone can't delete a
            # directory, so blocking `rm -f /` would be a false positive.
            # Accept any bundle containing `r` or `R`, plus the long form.
            rf"""\brm\s+
                (?:
                    (?:-[a-zA-Z]*[rR][a-zA-Z]*|--recursive)
                    (?:\s+-[a-zA-Z]+|\s+--[a-zA-Z]+)*       # optional further flags
                )
                \s+(?:--\s+)?
                {_DANGEROUS_PATH}
                (?=\s|$)
            """,
            re.VERBOSE,
        ),
        "Recursive delete targeting filesystem root, a system directory, or the user's home.",
    ),
    (
        "find / -delete",
        re.compile(
            rf"\bfind\s+{_DANGEROUS_PATH}(?=\s)[^|;&\n]*\s-delete\b"
        ),
        "Recursive deletion rooted at filesystem root, a system directory, or home.",
    ),
    (
        "chmod -R 777 catastrophic-path",
        re.compile(
            rf"""\bchmod\s+
                (?:-[a-zA-Z]*R[a-zA-Z]*|--recursive)        # require recursive
                (?:\s+-[a-zA-Z]+|\s+--[a-zA-Z]+)*
                \s+(?:0?777)\s+
                {_DANGEROUS_PATH}
                (?=\s|$)
            """,
            re.VERBOSE,
        ),
        "Recursively world-writable from filesystem root, a system directory, or home.",
    ),
    (
        "dd to block device",
        re.compile(r"\bdd\b[^|;&\n]*\bof=/dev/(?:sd[a-z]|disk\d|nvme\d|hd[a-z]|mmcblk\d)"),
        "Writes raw bytes to a block device — destroys the disk.",
    ),
    (
        "mkfs on block device",
        re.compile(r"\bmkfs(?:\.[a-z0-9]+)?\s+(?:-[^\s]+\s+)*/dev/(?:sd[a-z]|disk\d|nvme\d|hd[a-z])"),
        "Reformats a block device.",
    ),
    (
        "git force-push to main/master",
        re.compile(
            r"""\bgit\s+push\s+
                (?:--force\b|--force-with-lease\b|-f\b)
                [^|;&\n]*
                \b(?:main|master|trunk|production|prod)\b
            """,
            re.VERBOSE,
        ),
        "Force-push to a protected branch rewrites shared history.",
    ),
    (
        "git push --force to main (verb-then-flag)",
        re.compile(
            r"""\bgit\s+push\s+
                (?:[^\s|;&]+\s+)+                       # remote + branch tokens
                \b(?:main|master|trunk|production|prod)\b
                [^|;&\n]*
                (?:--force\b|--force-with-lease\b|\s-f\b)
            """,
            re.VERBOSE,
        ),
        "Force-push to a protected branch rewrites shared history.",
    ),
    (
        "terraform destroy (no --target)",
        re.compile(r"\b(?:terraform|tofu)\s+destroy\b(?![^|;&\n]*--target)"),
        "Tears down every resource in the state file. Use --target for surgical destroys.",
    ),
    (
        "kubectl delete namespace",
        re.compile(r"\bkubectl\s+(?:[^\s|;&]+\s+)*delete\s+(?:ns|namespaces?)\b"),
        "Deletes an entire namespace — every workload, every PVC, every secret.",
    ),
    (
        "kubectl delete --all without selector",
        re.compile(r"\bkubectl\s+(?:[^\s|;&]+\s+)*delete\s+[^\s|;&]+\s+--all\b(?![^|;&\n]*(?:--selector|-l\s))"),
        "Deletes every resource of the type — no label scope.",
    ),
    (
        "DROP DATABASE",
        re.compile(r"\bDROP\s+DATABASE\b", re.IGNORECASE),
        "Drops an entire database.",
    ),
    (
        "DROP TABLE",
        re.compile(r"\bDROP\s+TABLE\b(?!\s+IF\s+EXISTS\s+`?tmp)", re.IGNORECASE),
        "Drops a table.",
    ),
    (
        "shred / wipe device",
        re.compile(r"\b(?:shred|wipe)\b[^|;&\n]*?/dev/(?:sd[a-z]|disk\d|nvme\d|hd[a-z])"),
        "Destructive low-level erase of a block device.",
    ),
]


def main() -> int:
    try:
        return _run()
    except Exception:  # noqa: BLE001
        # Fail open — never wedge the user's bash on a hook bug.
        return 0


def _run() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0

    if payload.get("tool_name") != "Bash":
        return 0

    tool_input = payload.get("tool_input") or {}
    command = tool_input.get("command") or ""
    if not command.strip():
        return 0

    # Check each shell segment independently — catches
    # ``safe-cmd && rm -rf /`` and ``something ; terraform destroy``.
    for segment in _segments(command):
        for label, pattern, why in PATTERNS:
            if pattern.search(segment):
                _block(segment, label, why)
                return 2

    return 0


def _segments(command: str) -> list[str]:
    return [s for s in SEGMENT_SPLIT_RE.split(command) if s.strip()]


def _block(segment: str, label: str, why: str) -> None:
    msg = (
        f"BLOCKED by openclaw-os destruction-scan: matched pattern '{label}'.\n"
        f"Why: {why}\n"
        f"Segment: {segment.strip()[:200]}\n"
        f"\n"
        f"If this destruction is intentional and authorised, restart Claude Code\n"
        f"with OPENCLAW_ALLOW_DESTRUCTIVE=1 set in the shell — the guard is per-session\n"
        f"and clears when the session ends.\n"
        f"\n"
        f"If the match is wrong (false positive), open an issue with the segment\n"
        f"so the pattern can be tightened. The hook source is\n"
        f"~/.openclaw/guardrails/destruction-scan.py."
    )
    print(msg, file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
