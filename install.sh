#!/usr/bin/env bash
# install.sh — install @openclaw-os/security into an OpenClaw checkout.
#
# Usage from inside the OpenClaw repo root:
#   curl -fsSL https://raw.githubusercontent.com/Silverblock-Finance/openclaw-os/main/install.sh | bash
#
# Or against a specific OpenClaw checkout:
#   OPENCLAW_DIR=/path/to/openclaw \
#     curl -fsSL https://raw.githubusercontent.com/Silverblock-Finance/openclaw-os/main/install.sh | bash
#
# The repo is private. Auth resolution tries, in order:
#   1. `gh repo clone Silverblock-Finance/openclaw-os` (handles OAuth/MFA)
#   2. git over SSH      (git@github.com:Silverblock-Finance/openclaw-os.git)
#   3. git over HTTPS    (relies on git credential helper / PAT)
#
# Idempotent: if extensions/openclaw-os/ already exists as a git checkout of
# this repo, runs `git pull` instead of clone.

set -eo pipefail

REPO_SLUG="Silverblock-Finance/openclaw-os"
REPO_HTTPS="${OPENCLAW_OS_REPO_URL:-https://github.com/${REPO_SLUG}.git}"
REPO_SSH="git@github.com:${REPO_SLUG}.git"
OPENCLAW_DIR="${OPENCLAW_DIR:-$PWD}"
TARGET="${OPENCLAW_DIR%/}/extensions/openclaw-os"
WORKSPACE_FILE="${OPENCLAW_DIR%/}/pnpm-workspace.yaml"

say() { printf '\033[1;36m[openclaw-os]\033[0m %s\n' "$1"; }
die() { printf '\033[1;31m[openclaw-os]\033[0m %s\n' "$1" >&2; exit 1; }

# Sanity-check we're pointed at something that looks like OpenClaw.
[ -d "${OPENCLAW_DIR}" ] || die "OPENCLAW_DIR not found: ${OPENCLAW_DIR}"
[ -f "${OPENCLAW_DIR%/}/package.json" ] || die "no package.json at ${OPENCLAW_DIR} — point OPENCLAW_DIR at the OpenClaw repo root"
grep -q '"openclaw"' "${OPENCLAW_DIR%/}/package.json" 2>/dev/null \
  || say "warning: ${OPENCLAW_DIR}/package.json doesn't mention 'openclaw' — continuing anyway"

command -v git >/dev/null 2>&1 || die "git is required"

clone_repo() {
  if command -v gh >/dev/null 2>&1; then
    say "trying gh repo clone (handles GitHub OAuth/MFA) …"
    if gh repo clone "${REPO_SLUG}" "${TARGET}" -- --depth=1 2>/dev/null; then
      return 0
    fi
    say "gh clone failed — falling back to git"
  fi
  say "trying SSH (${REPO_SSH}) …"
  if git clone --depth=1 "${REPO_SSH}" "${TARGET}" 2>/dev/null; then
    return 0
  fi
  say "SSH clone failed — trying HTTPS (relies on git credential helper / PAT)"
  if git clone --depth=1 "${REPO_HTTPS}" "${TARGET}" 2>/dev/null; then
    return 0
  fi
  die "could not clone ${REPO_SLUG}. Auth options:
    - install gh + run 'gh auth login', then re-run this script
    - add an SSH key to your GitHub account
    - store a PAT in your git credential helper, then re-run"
}

# Clone or update.
if [ -d "${TARGET}/.git" ]; then
  say "extensions/openclaw-os already a git checkout — pulling"
  git -C "${TARGET}" pull --ff-only
elif [ -e "${TARGET}" ]; then
  die "${TARGET} exists but isn't a git checkout — move or delete it first"
else
  mkdir -p "${OPENCLAW_DIR%/}/extensions"
  clone_repo
fi

# Make sure pnpm-workspace.yaml includes extensions/*.
if [ -f "${WORKSPACE_FILE}" ]; then
  if ! grep -qE '^\s*-\s*["'\'']?extensions/\*' "${WORKSPACE_FILE}"; then
    say "adding 'extensions/*' to pnpm-workspace.yaml"
    printf '\n  - "extensions/*"\n' >> "${WORKSPACE_FILE}"
  fi
else
  say "no pnpm-workspace.yaml at ${OPENCLAW_DIR} — create one if pnpm doesn't auto-discover extensions/*"
fi

cat <<EOF

\033[1;32m✓\033[0m openclaw-os installed at ${TARGET}

Next steps:
  cd ${OPENCLAW_DIR}
  pnpm install
  # then start openclaw the usual way (e.g. pnpm dev)

Then in your openclaw config, under plugins.entries:

  openclaw-os:
    inboundClaim:    { scanSecrets: true, scanInjection: true, redactSecrets: true, blockOnInjection: false }
    beforeToolCall:  { destruction: true, scanParamSecrets: true }
    afterToolCall:   { scanReadResultsForInjection: true, scanShellOutputForSecrets: true }

Look for \`[openclaw-os] …\` lines in stderr to see findings.
Docs: https://github.com/Silverblock-Finance/openclaw-os
EOF
