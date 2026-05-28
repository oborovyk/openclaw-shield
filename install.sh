#!/usr/bin/env bash
# install.sh — CONTRIBUTOR INSTALL ONLY.
#
# This script is for developers running OpenClaw from a source-built `git clone`
# of the openclaw repo who want this plugin in the same workspace. It drops the
# plugin into `<openclaw>/extensions/openclaw-shield/` and edits pnpm-workspace.yaml.
#
# END USERS — on Docker, nix, npm-global, or any other deployment — should NOT
# run this. Use openclaw's native CLI instead:
#
#   openclaw plugins install git:github.com/Silverblock-Finance/openclaw-shield
#   openclaw plugins enable openclaw-shield
#
# That handles the right install path for whatever shape of openclaw you run.
# See README.md → "Install" for full details.
#
# ─── Contributor usage ─────────────────────────────────────────────────────
# Install (run from the OpenClaw repo root):
#   curl -fsSL https://raw.githubusercontent.com/Silverblock-Finance/openclaw-shield/main/install.sh | bash
#
# Uninstall:
#   curl -fsSL .../install.sh | bash -s -- --uninstall
#
# Knobs:
#   OPENCLAW_DIR=/path/to/openclaw       target a non-cwd OpenClaw checkout
#   OPENCLAW_SHIELD_REPO_URL=<git url>       override clone URL (default github HTTPS)
#   OPENCLAW_SHIELD_FORCE=1                  skip the safety prompts during uninstall
#
# What this script touches (and only this):
#   <OPENCLAW_DIR>/extensions/openclaw-shield/         created (install) / removed (uninstall)
#   <OPENCLAW_DIR>/pnpm-workspace.yaml             one-line append (install only) — see notes
#
# Uninstall does NOT revert the pnpm-workspace.yaml edit (`extensions/*` glob is
# a generic openclaw pattern, harmless to leave). It also does NOT touch your
# openclaw runtime config under plugins.entries — remove that block manually.

set -eo pipefail

REPO_SLUG="Silverblock-Finance/openclaw-shield"
REPO_HTTPS="${OPENCLAW_SHIELD_REPO_URL:-https://github.com/${REPO_SLUG}.git}"
REPO_SSH="git@github.com:${REPO_SLUG}.git"
OPENCLAW_DIR="${OPENCLAW_DIR:-$PWD}"
TARGET="${OPENCLAW_DIR%/}/extensions/openclaw-shield"
WORKSPACE_FILE="${OPENCLAW_DIR%/}/pnpm-workspace.yaml"
FORCE="${OPENCLAW_SHIELD_FORCE:-0}"

MODE="install"
for arg in "$@"; do
  case "$arg" in
    --uninstall) MODE="uninstall" ;;
    --help|-h)   MODE="help" ;;
  esac
done

say()  { printf '\033[1;36m[openclaw-shield]\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33m[openclaw-shield]\033[0m %s\n' "$1" >&2; }
die()  { printf '\033[1;31m[openclaw-shield]\033[0m %s\n' "$1" >&2; exit 1; }

if [ "$MODE" = "help" ]; then
  sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
fi

[ -d "${OPENCLAW_DIR}" ] || die "OPENCLAW_DIR not found: ${OPENCLAW_DIR}"

# ─── UNINSTALL ───────────────────────────────────────────────────────────────
if [ "$MODE" = "uninstall" ]; then
  if [ ! -d "${TARGET}" ]; then
    say "nothing to uninstall: ${TARGET} does not exist"
    exit 0
  fi

  # Refuse to delete uncommitted work without explicit consent.
  if [ -d "${TARGET}/.git" ] && command -v git >/dev/null 2>&1; then
    if ! git -C "${TARGET}" diff --quiet 2>/dev/null || \
       ! git -C "${TARGET}" diff --cached --quiet 2>/dev/null || \
       [ -n "$(git -C "${TARGET}" ls-files --others --exclude-standard 2>/dev/null)" ]; then
      warn "${TARGET} has uncommitted changes (staged, unstaged, or untracked files)."
      if [ "$FORCE" != "1" ]; then
        die "refusing to delete. Commit/stash your work, or re-run with OPENCLAW_SHIELD_FORCE=1."
      fi
      warn "OPENCLAW_SHIELD_FORCE=1 — deleting anyway."
    fi
  fi

  say "removing ${TARGET}"
  rm -rf "${TARGET}"

  cat <<EOF

\033[1;32m✓\033[0m openclaw-shield uninstalled.

The 'extensions/*' line in pnpm-workspace.yaml (if added by install) was left
in place — it's a generic openclaw pattern and harmless to keep.

If you had this plugin enabled in your openclaw runtime config, remove the
\`plugins.entries.openclaw-shield\` block manually so openclaw doesn't warn at
startup.

Then run \`pnpm install\` in ${OPENCLAW_DIR} to clean up the workspace link.
EOF
  exit 0
fi

# ─── INSTALL ────────────────────────────────────────────────────────────────
[ -f "${OPENCLAW_DIR%/}/package.json" ] || die "no package.json at ${OPENCLAW_DIR} — point OPENCLAW_DIR at the OpenClaw repo root"
grep -q '"openclaw"' "${OPENCLAW_DIR%/}/package.json" 2>/dev/null \
  || warn "${OPENCLAW_DIR}/package.json doesn't mention 'openclaw' — continuing anyway"

command -v git >/dev/null 2>&1 || die "git is required"

# Show the user what we're about to touch.
say "about to install into ${OPENCLAW_DIR}"
say "  - create / update directory: ${TARGET}"
if [ -f "${WORKSPACE_FILE}" ] && ! grep -qE '^\s*-\s*["'\'']?extensions/\*' "${WORKSPACE_FILE}"; then
  say "  - append 'extensions/*' to ${WORKSPACE_FILE}"
fi

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

# Clone or fast-forward.
if [ -d "${TARGET}/.git" ]; then
  say "extensions/openclaw-shield already a git checkout — pulling (--ff-only)"
  git -C "${TARGET}" pull --ff-only || die "pull failed — resolve local changes in ${TARGET} or re-run with --uninstall"
elif [ -e "${TARGET}" ]; then
  die "${TARGET} exists but isn't a git checkout — move or delete it first"
else
  mkdir -p "${OPENCLAW_DIR%/}/extensions"
  clone_repo
fi

# pnpm-workspace.yaml: only edit if the file already has a `packages:` key (so
# `extensions/*` lands in the right list). If the user doesn't use a workspace
# file, leave it alone — pnpm may auto-discover, or they may have a different
# layout we shouldn't second-guess.
if [ -f "${WORKSPACE_FILE}" ]; then
  if grep -qE '^\s*-\s*["'\'']?extensions/\*' "${WORKSPACE_FILE}"; then
    say "pnpm-workspace.yaml already includes extensions/* — skipping edit"
  elif grep -qE '^packages:' "${WORKSPACE_FILE}"; then
    # Safe append — file already has the packages: section we'll fall under.
    say "appending 'extensions/*' to ${WORKSPACE_FILE}"
    cp "${WORKSPACE_FILE}" "${WORKSPACE_FILE}.openclaw-shield-bak"
    printf '  - "extensions/*"\n' >> "${WORKSPACE_FILE}"
    say "  (backup saved to ${WORKSPACE_FILE}.openclaw-shield-bak)"
  else
    warn "${WORKSPACE_FILE} does not declare a 'packages:' list — leaving it untouched. Add 'extensions/*' manually if pnpm doesn't pick the plugin up."
  fi
else
  warn "no pnpm-workspace.yaml at ${OPENCLAW_DIR} — pnpm may auto-discover extensions/* or you may need to create one"
fi

cat <<EOF

\033[1;32m✓\033[0m openclaw-shield installed at ${TARGET}

Next steps:
  cd ${OPENCLAW_DIR}
  pnpm install
  # then start openclaw the usual way (e.g. pnpm dev)

Then in your openclaw config, under plugins.entries:

  openclaw-shield:
    inboundClaim:    { scanSecrets: true, scanInjection: true, redactSecrets: true, blockOnInjection: false }
    beforeToolCall:  { destruction: true, scanParamSecrets: true }
    afterToolCall:   { scanReadResultsForInjection: true, scanShellOutputForSecrets: true }

To uninstall later:
  curl -fsSL https://raw.githubusercontent.com/Silverblock-Finance/openclaw-shield/main/install.sh | bash -s -- --uninstall

Docs: https://github.com/Silverblock-Finance/openclaw-shield
EOF
