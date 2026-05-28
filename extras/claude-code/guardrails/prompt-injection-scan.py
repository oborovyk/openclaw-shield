#!/usr/bin/env python3
"""prompt-injection-scan.py — Scan files for prompt-injection patterns.

Ported from prompt-injection-scan.sh. Single process, regexes compiled once,
each file read and scanned in one pass instead of once per pattern.
Cuts a 16-file staged scan from ~1.5s to ~80ms.

Usage:
    prompt-injection-scan.py --diff [BASE]     # CI-style: scan changed files
    prompt-injection-scan.py --staged          # git index (pre-commit)
    prompt-injection-scan.py --file PATH       # single file
    prompt-injection-scan.py --dir PATH        # all files under a directory
    prompt-injection-scan.py --stdin           # read file paths from stdin

Exit codes:
    0 — clean
    1 — findings detected
    2 — usage error
"""

import argparse
import fnmatch
import os
import re
import subprocess
import sys
from pathlib import Path


PATTERNS = [
    # Instruction override
    r"ignore\s+(all\s+)?(previous|prior|above|earlier|preceding)\s+(instructions|prompts|rules|directives|context)",
    r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)",
    r"forget\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules|context)",
    r"override\s+(all\s+)?(system|previous|safety)\s+(instructions|prompts|rules|checks|filters|guards)",
    r"override\s+(system|safety|security)\s+",

    # Role manipulation
    r"you\s+are\s+now\s+(a|an|my)\s+",
    r"from\s+now\s+on\s+(you|pretend|act|behave)",
    r"pretend\s+(you\s+are|to\s+be)\s+",
    r"act\s+as\s+(a|an|if|my)\s+",
    r"roleplay\s+as\s+",
    r"assume\s+the\s+role\s+of\s+",

    # System prompt extraction
    r"output\s+(your|the)\s+(system\s+)?(prompt|instructions)",
    r"reveal\s+(your|the)\s+(system\s+)?(prompt|instructions)",
    r"show\s+me\s+(your|the)\s+(system\s+)?(prompt|instructions)",
    r"print\s+(your|the)\s+(system\s+)?(prompt|instructions)",
    r"what\s+(is|are)\s+(your|the)\s+(system\s+)?(prompt|instructions)",
    r"repeat\s+(your|the|all)\s+(system\s+)?(prompt|instructions|rules)",

    # Fake message boundaries
    r"</?system>",
    r"</?assistant>",
    r"</?human>",
    r"\[SYSTEM\]",
    r"\[/SYSTEM\]",
    r"\[INST\]",
    r"\[/INST\]",
    r"<<SYS>>",
    r"<</SYS>>",

    # Tool call injection / code execution in markdown
    r"""eval\s*\(\s*['"]""",
    r"""exec\s*\(\s*['"]""",
    r"""Function\s*\(\s*['"].*return""",

    # Jailbreak / DAN
    r"do\s+anything\s+now",
    r"DAN\s+mode",
    r"developer\s+mode\s+(enabled|output|activated)",
    r"jailbreak",
    r"bypass\s+(safety|content|security)\s+(filter|check|rule|guard)",
]

COMPILED = [re.compile(p, re.IGNORECASE) for p in PATTERNS]

SCANNABLE_EXTS = {".md", ".cjs", ".js", ".json", ".yml", ".yaml", ".sh", ".py", ".ts", ".tsx"}

SKIP_DIR_PARTS = {"node_modules", "venv", "__pycache__", ".git", "dist"}

IGNOREFILE = ".secretscanignore"


def load_ignorelist() -> list[str]:
    """Load glob patterns from .secretscanignore in cwd. Shared across all
    openclaw-os scanners — one list, one mental model."""
    ignore_path = Path.cwd() / IGNOREFILE
    if not ignore_path.is_file():
        return []
    globs = []
    for raw in ignore_path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        globs.append(line)
    return globs


def is_ignored(path: str, globs: list[str]) -> bool:
    """Match path against .secretscanignore globs. Patterns with '/' match the
    full or relative path; patterns without match the basename only."""
    if not globs:
        return False
    name = os.path.basename(path)
    try:
        rel = os.path.relpath(path)
    except (ValueError, OSError):
        rel = path
    for pattern in globs:
        if "/" not in pattern:
            if fnmatch.fnmatch(name, pattern):
                return True
        elif (fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(path, pattern)
              or fnmatch.fnmatch(rel, f"*/{pattern}")
              or fnmatch.fnmatch(path, f"*/{pattern}")):
            return True
    return False


def is_scannable(path: Path) -> bool:
    if path.suffix.lower() not in SCANNABLE_EXTS:
        return False
    if any(part in SKIP_DIR_PARTS for part in path.parts):
        return False
    return True


def git_diff_files(base: str | None, staged: bool) -> list[str]:
    if staged:
        cmd = ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"]
    else:
        ref = base or "origin/main"
        cmd = ["git", "diff", "--name-only", "--diff-filter=ACMR", f"{ref}...HEAD"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return []
    return [f for f in result.stdout.splitlines()
            if f and Path(f).suffix.lower() in SCANNABLE_EXTS]


def collect_files(args: argparse.Namespace) -> list[str]:
    if args.diff is not None:
        return git_diff_files(args.diff, staged=False)
    if args.staged:
        return git_diff_files(None, staged=True)
    if args.file:
        if not Path(args.file).is_file():
            print(f"Error: file not found: {args.file}", file=sys.stderr)
            sys.exit(2)
        return [args.file]
    if args.dir:
        d = Path(args.dir)
        if not d.is_dir():
            print(f"Error: directory not found: {args.dir}", file=sys.stderr)
            sys.exit(2)
        return [str(p) for p in d.rglob("*") if p.is_file() and is_scannable(p)]
    if args.stdin:
        return [line.strip() for line in sys.stdin if line.strip()]
    return []


def scan_file(path: str, globs: list[str]) -> bool:
    """Return True if any findings, False if clean."""
    if is_ignored(path, globs):
        return False
    try:
        content = Path(path).read_bytes().decode("utf-8", errors="replace")
    except OSError:
        return False

    findings: list[tuple[int, str]] = []
    for regex in COMPILED:
        for m in regex.finditer(content):
            line_no = content.count("\n", 0, m.start()) + 1
            line_start = content.rfind("\n", 0, m.start()) + 1
            line_end = content.find("\n", m.end())
            if line_end == -1:
                line_end = len(content)
            findings.append((line_no, content[line_start:line_end]))

    if not findings:
        return False

    print(f"FAIL: {path}")
    for line_no, line in findings:
        print(f"  {line_no}:{line}")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(add_help=True, description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--diff", nargs="?", const="origin/main", default=None, metavar="BASE")
    group.add_argument("--staged", action="store_true")
    group.add_argument("--file", metavar="PATH")
    group.add_argument("--dir", metavar="PATH")
    group.add_argument("--stdin", action="store_true")
    args = parser.parse_args()

    globs = load_ignorelist()
    files = collect_files(args)

    if not files:
        print("prompt-injection-scan: no files to scan")
        sys.exit(0)

    total = 0
    failed = 0
    for f in files:
        total += 1
        if scan_file(f, globs):
            failed += 1

    print(f"\nprompt-injection-scan: scanned {total} files, {failed} with findings")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
