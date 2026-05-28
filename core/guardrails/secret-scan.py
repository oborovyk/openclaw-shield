#!/usr/bin/env python3
"""secret-scan.py — Check files for accidentally committed secrets/credentials.

Ported from secret-scan.sh. Compiles regexes once and applies them in a single
pass per file, avoiding the N×M grep fork overhead of the shell version.
Cuts a 16-file staged scan from ~1.2s to ~60ms.

Usage:
    secret-scan.py --diff [BASE]         # CI-style: scan changed files
    secret-scan.py --staged              # git index (pre-commit)
    secret-scan.py --file PATH           # single file
    secret-scan.py --dir PATH            # all files under a directory
    secret-scan.py --stdin               # read file paths from stdin

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


SECRET_PATTERNS = [
    # AWS
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret Key", r"aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}"),

    # AI providers
    ("OpenAI API Key", r"sk-[A-Za-z0-9]{20,}"),
    ("Anthropic API Key", r"sk-ant-[A-Za-z0-9_\-]{20,}"),

    # GitHub
    ("GitHub PAT", r"ghp_[A-Za-z0-9]{36}"),
    ("GitHub OAuth", r"gho_[A-Za-z0-9]{36}"),
    ("GitHub App Token", r"ghs_[A-Za-z0-9]{36}"),
    ("GitHub Fine-grained PAT", r"github_pat_[A-Za-z0-9_]{20,}"),

    # GitLab (Silverblock uses GitLab Ultimate)
    ("GitLab PAT", r"glpat-[A-Za-z0-9_\-]{20,}"),
    ("GitLab Deploy Token", r"gldt-[A-Za-z0-9_\-]{20,}"),
    ("GitLab OAuth", r"glrt-[A-Za-z0-9_\-]{20,}"),

    # Atlassian (Jira/Confluence API tokens)
    ("Atlassian API Token", r"ATATT3[A-Za-z0-9_\-]{20,}"),

    # Stripe
    ("Stripe Secret Key", r"sk_live_[A-Za-z0-9]{24,}"),
    ("Stripe Publishable Key", r"pk_live_[A-Za-z0-9]{24,}"),

    # Generic
    ("Private Key Header", r"-----BEGIN\s+(RSA|EC|DSA|OPENSSH)?\s*PRIVATE\s+KEY-----"),
    ("Generic API Key Assignment", r"""api[_-]?key\s*[:=]\s*['"][A-Za-z0-9_\-]{20,}['"]"""),
    ("Generic Secret Assignment",  r"""secret\s*[:=]\s*['"][A-Za-z0-9_\-]{20,}['"]"""),
    ("Generic Token Assignment",   r"""token\s*[:=]\s*['"][A-Za-z0-9_\-]{20,}['"]"""),
    ("Generic Password Assignment", r"""password\s*[:=]\s*['"][^'"]{8,}['"]"""),

    # Slack
    ("Slack Bot Token", r"xoxb-[0-9]{10,}-[A-Za-z0-9]{20,}"),
    ("Slack Webhook", r"hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}"),

    # Google
    ("Google API Key", r"AIza[A-Za-z0-9_\-]{35}"),

    # NPM
    ("NPM Token", r"npm_[A-Za-z0-9]{36}"),

    # .env-style sensitive keys
    ("Env Variable Leak",
     r"(DATABASE_URL|DB_PASSWORD|REDIS_URL|MONGO_URI|JWT_SECRET|SESSION_SECRET|ENCRYPTION_KEY)"
     r"\s*=\s*\S{8,}"),
]

# Compile once.
COMPILED = [(label, re.compile(pattern)) for label, pattern in SECRET_PATTERNS]

SKIP_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
}
SKIP_NAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "secret-scan.sh", "secret-scan.py",
}
SKIP_DIR_PARTS = {"node_modules", "venv", "__pycache__", ".git", "dist"}

IGNOREFILE = ".secretscanignore"

# Line-level suppression: if a matched line contains any of these markers the
# finding is silently skipped.  ENC(...) is a Jasypt-encrypted ciphertext —
# the value is already encrypted and safe to commit.
SAFE_LINE_MARKERS = [
    "ENC(",   # Jasypt encrypted property: password: ENC(xyz...)
]


def should_skip_file(path: Path) -> bool:
    if path.suffix.lower() in SKIP_EXTS:
        return True
    if path.name in SKIP_NAMES:
        return True
    if any(part in SKIP_DIR_PARTS for part in path.parts):
        return True
    return False


def load_ignorelist() -> list[str]:
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
    return [f for f in result.stdout.splitlines() if f]


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
        return [str(p) for p in d.rglob("*") if p.is_file()]
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

    findings: list[tuple[str, int, str]] = []
    for label, regex in COMPILED:
        for m in regex.finditer(content):
            line_no = content.count("\n", 0, m.start()) + 1
            line_start = content.rfind("\n", 0, m.start()) + 1
            line_end = content.find("\n", m.end())
            if line_end == -1:
                line_end = len(content)
            line_text = content[line_start:line_end]
            if any(marker in line_text for marker in SAFE_LINE_MARKERS):
                continue
            findings.append((label, line_no, line_text))

    if not findings:
        return False

    print(f"FAIL: {path}")
    for label, line_no, line in findings:
        print(f"  [{label}] {line_no}:{line}")
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
        print("secret-scan: no files to scan")
        sys.exit(0)

    total = 0
    failed = 0
    for f in files:
        if should_skip_file(Path(f)):
            continue
        total += 1
        if scan_file(f, globs):
            failed += 1

    print(f"\nsecret-scan: scanned {total} files, {failed} with findings")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
