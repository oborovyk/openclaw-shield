// before_tool_call hook — runs before every tool execution.
//
// We block on:
//   - Destruction patterns matched against shell-exec tools (`bash`, `exec` are
//     openclaw's canonical names; additional tool names are caught by the
//     keyword fallback).
//   - Secret patterns matched against any string param value.

import type {
  PluginHookBeforeToolCallEvent,
  PluginHookBeforeToolCallResult,
} from "openclaw/plugins/hook-types";
import { scanDestruction } from "../patterns/destruction-rules.js";
import { scanSecrets } from "../patterns/secret-patterns.js";
import type { GuardrailsConfig } from "../config.js";

// Canonical openclaw shell-tool names. Verified against
// openclaw/src/agents/sessions/tools/bash.ts:287 ("bash") and
// openclaw/src/agents/bash-tools.exec.ts:1276 ("exec"). Both use a `command`
// string param.
const KNOWN_SHELL_TOOLS = new Set(["bash", "exec"]);
const SHELL_TOOL_HINTS = ["bash", "shell", "exec", "terminal", "subprocess"];

function looksLikeShellTool(name: string): boolean {
  const n = name.toLowerCase();
  if (KNOWN_SHELL_TOOLS.has(n)) return true;
  return SHELL_TOOL_HINTS.some((h) => n.includes(h));
}

function extractCommand(params: Record<string, unknown>): string | null {
  // Canonical openclaw shell-tool param is `command`. The `script` and
  // `cmd` fallbacks cover third-party tools authored against a different
  // convention. We never fall back to scanning all params for destructive
  // patterns — that would flag documentation that mentions e.g. `rm -rf /`.
  for (const key of ["command", "script", "cmd"]) {
    const v = params[key];
    if (typeof v === "string") return v;
  }
  return null;
}

function flattenStringParams(params: Record<string, unknown>): string[] {
  const out: string[] = [];
  const walk = (v: unknown): void => {
    if (typeof v === "string") out.push(v);
    else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === "object") {
      for (const inner of Object.values(v as Record<string, unknown>)) walk(inner);
    }
  };
  walk(params);
  return out;
}

export function makeBeforeToolCallHandler(
  config: GuardrailsConfig,
  log: (line: string) => void,
) {
  return (
    event: PluginHookBeforeToolCallEvent,
  ): PluginHookBeforeToolCallResult | void => {
    const cfg = config.beforeToolCall;

    if (cfg.destruction && looksLikeShellTool(event.toolName)) {
      const command = extractCommand(event.params);
      if (command !== null) {
        const hit = scanDestruction(command);
        if (hit) {
          log(`before_tool_call: BLOCK ${event.toolName} — ${hit.label}: ${hit.match}`);
          return {
            block: true,
            blockReason: `openclaw-shield destruction-scan: ${hit.label}. ${hit.reason}`,
          };
        }
      }
    }

    if (cfg.scanParamSecrets) {
      for (const s of flattenStringParams(event.params)) {
        const findings = scanSecrets(s);
        if (findings.length > 0) {
          log(`before_tool_call: BLOCK ${event.toolName} — secret in params: ${findings[0].label}`);
          return {
            block: true,
            blockReason: `openclaw-shield secret-scan: ${findings[0].label} in tool parameter. Tool call refused.`,
          };
        }
      }
    }
  };
}
