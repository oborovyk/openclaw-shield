// before_tool_call hook — runs before every tool execution.
//
// We block on:
//   - Destruction patterns matched against shell-exec tools (e.g. `bash`, `shell`,
//     `command`, `exec`). Tool naming varies across providers, so we match by
//     keyword in `toolName` rather than an exact list.
//   - Secret patterns matched against any string param value.

import type {
  PluginHookBeforeToolCallEvent,
  PluginHookBeforeToolCallResult,
} from "openclaw/plugins/hook-types";
import { scanDestruction } from "../patterns/destruction-rules.js";
import { scanSecrets } from "../patterns/secret-patterns.js";
import type { GuardrailsConfig } from "../config.js";

const SHELL_TOOL_HINTS = ["bash", "shell", "command", "exec", "run", "terminal"];

function looksLikeShellTool(name: string): boolean {
  const n = name.toLowerCase();
  return SHELL_TOOL_HINTS.some((h) => n.includes(h));
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
      // Best-effort extraction of the command string from the tool params.
      const candidate =
        (event.params as { command?: unknown })?.command ??
        (event.params as { cmd?: unknown })?.cmd ??
        (event.params as { input?: unknown })?.input;
      if (typeof candidate === "string") {
        const hit = scanDestruction(candidate);
        if (hit) {
          log(`before_tool_call: BLOCK ${event.toolName} — ${hit.label}: ${hit.match}`);
          return {
            block: true,
            blockReason: `openclaw-os destruction-scan: ${hit.label}. ${hit.reason}`,
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
            blockReason: `openclaw-os secret-scan: ${findings[0].label} in tool parameter. Tool call refused.`,
          };
        }
      }
    }
  };
}
