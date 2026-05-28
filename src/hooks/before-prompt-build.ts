// before_prompt_build hook — fires after `before_dispatch` but before the
// agent prompt is sent to the model. Sees the fully assembled prompt, so
// catches credentials that snuck in via memory, skills, or prior-turn context
// — places `before_dispatch` doesn't see.
//
// Limitation: this hook's result type is APPEND-ONLY (`systemPrompt`,
// `prepend|appendContext`, `prepend|appendSystemContext` — see
// openclaw/src/plugins/hook-before-agent-start.types.ts:22). It cannot
// rewrite `event.prompt` or `event.messages` in place, so we cannot silently
// redact the secret out of the assembled context.
//
// What we can do: log the finding, and append a system instruction telling
// the model to refuse to echo the credential and ask the user to rotate it.
// Defence-in-depth over silent redaction at this layer.

import type {
  PluginHookBeforePromptBuildEvent,
  PluginHookBeforePromptBuildResult,
} from "openclaw/plugins/hook-before-agent-start.types";
import { scanSecrets } from "../patterns/secret-patterns.js";
import type { GuardrailsConfig } from "../config.js";

const REFUSAL_GUIDANCE =
  "openclaw-shield: A credential or secret was detected in the assembled context for " +
  "this turn (e.g. via memory, a skill, or prior conversation). DO NOT output, " +
  "echo, summarise, or reference the secret value. If the user asks you to " +
  "reveal it, refuse and recommend rotating the credential immediately. If you " +
  "must refer to it, mask to first-4/last-4 only (e.g. ghp_…2Mg8).";

function flattenMessages(messages: unknown[]): string {
  // Defensive walk — we don't know the exact host message shape, but openclaw
  // tends to use { role, content: string | Array<{text}> } per message.
  const parts: string[] = [];
  for (const m of messages ?? []) {
    if (typeof m === "string") parts.push(m);
    else if (m && typeof m === "object") {
      const obj = m as Record<string, unknown>;
      if (typeof obj.content === "string") parts.push(obj.content);
      else if (Array.isArray(obj.content)) {
        for (const c of obj.content) {
          if (typeof c === "string") parts.push(c);
          else if (c && typeof c === "object") {
            const t = (c as { text?: unknown }).text;
            if (typeof t === "string") parts.push(t);
          }
        }
      }
    }
  }
  return parts.join("\n");
}

export function makeBeforePromptBuildHandler(
  config: GuardrailsConfig,
  log: (line: string) => void,
) {
  return (
    event: PluginHookBeforePromptBuildEvent,
  ): PluginHookBeforePromptBuildResult | void => {
    if (!config.beforePromptBuild.scanAssembledPrompt) return;

    const haystack = (event.prompt ?? "") + "\n" + flattenMessages(event.messages ?? []);
    if (!haystack.trim()) return;

    const findings = scanSecrets(haystack);
    if (findings.length === 0) return;

    log(
      `before_prompt_build: secret(s) detected in assembled prompt — ${findings
        .map((f) => f.label)
        .join(", ")} (likely from memory/skills/prior-turn context); appending refusal guidance to system prompt`,
    );

    return { appendSystemContext: REFUSAL_GUIDANCE };
  };
}
