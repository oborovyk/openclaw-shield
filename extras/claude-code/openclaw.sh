#!/usr/bin/env bash
# openclaw-os CLI — provider-neutral guardrails + skills for coding agents.
#
# Verbs:
#   install                  Install guardrails to ~/.openclaw/guardrails/ and
#                            wire the Claude Code hook entries into
#                            ~/.claude/settings.json. Idempotent.
#   uninstall                Reverse the above.
#   scan <name> [args...]    Run a guardrail. <name> is one of:
#                              secret, injection, read-injection,
#                              bash-output, destruction
#                            All args after the name are forwarded to the
#                            underlying Python scanner (e.g. --staged,
#                            --diff origin/main, --dir ., --file path).
#   list                     List installed guardrails.
#   help                     Show this help.
#
# Exit codes from `scan` mirror the guardrail contract:
#   0 allow, 1 warn, 2 block.

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARDRAILS_DIR="${SCRIPT_DIR}/guardrails"

GUARDRAIL_NAMES="secret injection read-injection bash-output destruction"

guardrail_script() {
  case "$1" in
    secret)         echo "secret-scan.py" ;;
    injection)      echo "prompt-injection-scan.py" ;;
    read-injection) echo "read-injection-scanner.py" ;;
    bash-output)    echo "bash-output-secret-scan.py" ;;
    destruction)    echo "destruction-scan.py" ;;
    *)              return 1 ;;
  esac
}

cmd_scan() {
  if [ $# -lt 1 ]; then
    echo "usage: openclaw scan <name> [args...]" >&2
    echo "names: ${GUARDRAIL_NAMES}" >&2
    return 64
  fi
  local name="$1"; shift
  local script
  if ! script="$(guardrail_script "$name")"; then
    echo "error: unknown guardrail '$name'" >&2
    echo "available: ${GUARDRAIL_NAMES}" >&2
    return 64
  fi
  exec python3 "${GUARDRAILS_DIR}/${script}" "$@"
}

cmd_list() {
  printf "%-16s  %s\n" "NAME" "SCRIPT"
  for name in ${GUARDRAIL_NAMES}; do
    printf "%-16s  %s\n" "$name" "extras/claude-code/guardrails/$(guardrail_script "$name")"
  done
}

cmd_help() {
  sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

cmd_install() {
  chmod +x "${SCRIPT_DIR}/install.sh"
  exec "${SCRIPT_DIR}/install.sh" install "${SCRIPT_DIR}"
}

cmd_uninstall() {
  exec "${SCRIPT_DIR}/install.sh" uninstall
}

main() {
  local cmd="${1:-help}"
  shift || true
  case "$cmd" in
    install)   cmd_install ;;
    uninstall) cmd_uninstall ;;
    scan)      cmd_scan "$@" ;;
    list)      cmd_list ;;
    help|-h|--help) cmd_help ;;
    *)
      echo "error: unknown command '$cmd'" >&2
      cmd_help >&2
      exit 64
      ;;
  esac
}

main "$@"
