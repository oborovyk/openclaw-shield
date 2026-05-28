// before_dispatch hook — runs after inbound_claim and before the agent prompt
// is built. The result type `{ handled: boolean; text?: string }` lets us
// rewrite the body the agent will see (see openclaw/src/auto-reply/reply/
// dispatch-from-config.ts:1886). This is where secret redaction actually
// takes effect.
//
// Note: this hook only fires when the host has before_dispatch hooks registered
// AND the conversation reaches dispatch. inbound_claim already logged the
// finding; here we just rewrite.

import type {
  PluginHookBeforeDispatchEvent,
  PluginHookBeforeDispatchResult,
} from "openclaw/plugins/hook-types";
import { redactSecrets } from "../patterns/secret-patterns.js";
import type { GuardrailsConfig } from "../config.js";

export function makeBeforeDispatchHandler(
  config: GuardrailsConfig,
  log: (line: string) => void,
) {
  return (
    event: PluginHookBeforeDispatchEvent,
  ): PluginHookBeforeDispatchResult | void => {
    const cfg = config.inboundClaim;
    if (!cfg.scanSecrets || !cfg.redactSecrets) return;

    const text = event.body ?? event.content ?? "";
    if (!text) return;

    const { text: cleaned, findings } = redactSecrets(text);
    if (findings.length === 0 || cleaned === text) return;

    log(
      `before_dispatch: redacted ${findings.length} credential(s) before agent saw the message: ` +
        findings.map((f) => f.label).join(", "),
    );
    return { handled: false, text: cleaned };
  };
}
