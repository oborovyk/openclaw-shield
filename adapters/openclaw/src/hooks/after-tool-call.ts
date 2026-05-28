// after_tool_call hook — runs after every tool returns. Observation-only (cannot
// retroactively block) but logs findings so they show up in audit and can be
// surfaced to operators / future model turns via the host's diagnostic trace.
//
// Two scans:
//   - Shell-output secret scan: tools that look like a shell, scan stdout/stderr for credentials.
//   - Read-injection scan: tools that look like file/url readers, scan result for prompt-injection.

import type {
  PluginHookAfterToolCallEvent,
} from "openclaw/plugins/hook-types";
import { scanSecrets } from "../patterns/secret-patterns.js";
import { scanInjection } from "../patterns/injection-patterns.js";
import type { GuardrailsConfig } from "../config.js";

const SHELL_HINTS = ["bash", "shell", "command", "exec", "run", "terminal"];
const READ_HINTS = ["read", "fetch", "get", "fileread", "open", "cat", "view", "browse", "download"];

function nameMatches(name: string, hints: string[]): boolean {
  const n = name.toLowerCase();
  return hints.some((h) => n.includes(h));
}

function stringifyResult(result: unknown): string {
  if (result == null) return "";
  if (typeof result === "string") return result;
  try {
    return JSON.stringify(result);
  } catch {
    return String(result);
  }
}

export function makeAfterToolCallHandler(
  config: GuardrailsConfig,
  log: (line: string) => void,
) {
  return (event: PluginHookAfterToolCallEvent): void => {
    const cfg = config.afterToolCall;
    if (event.error) return; // failed tool calls have no useful payload

    const text = stringifyResult(event.result);
    if (!text) return;

    if (cfg.scanShellOutputForSecrets && nameMatches(event.toolName, SHELL_HINTS)) {
      const findings = scanSecrets(text);
      if (findings.length > 0) {
        log(
          `after_tool_call: ⚠ secret(s) in ${event.toolName} output — ` +
            findings.map((f) => f.label).join(", ") +
            ". DO NOT echo full value; mask to first-4/last-4.",
        );
      }
    }

    if (cfg.scanReadResultsForInjection && nameMatches(event.toolName, READ_HINTS)) {
      const findings = scanInjection(text);
      if (findings.length > 0) {
        log(
          `after_tool_call: ⚠ prompt-injection pattern(s) in ${event.toolName} result — ` +
            findings.slice(0, 3).map((f) => f.match).join(" | "),
        );
      }
    }
  };
}
