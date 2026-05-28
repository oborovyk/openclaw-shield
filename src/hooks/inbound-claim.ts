// inbound_claim hook — runs once per claimed inbound channel message (Telegram, WhatsApp, …).
// We do NOT take ownership of the message (return handled:false). We only:
//   (a) scan the message text for credentials and optionally redact them
//   (b) scan the message text for prompt-injection patterns and warn
//
// Blocking is intentionally off by default — false-positive risk on user chat
// text is too high. Enable via config: inboundClaim.blockOnInjection = true.

import type {
  PluginHookInboundClaimEvent,
  PluginHookInboundClaimResult,
} from "openclaw/plugins/hook-message.types";
import { redactSecrets, scanSecrets } from "../patterns/secret-patterns.js";
import { scanInjection } from "../patterns/injection-patterns.js";
import type { GuardrailsConfig } from "../config.js";

export function makeInboundClaimHandler(
  config: GuardrailsConfig,
  log: (line: string) => void,
) {
  return (
    event: PluginHookInboundClaimEvent,
  ): PluginHookInboundClaimResult | void => {
    const cfg = config.inboundClaim;
    if (!cfg.scanSecrets && !cfg.scanInjection) return;

    const text = event.bodyForAgent ?? event.body ?? event.content ?? "";
    if (!text) return;

    if (cfg.scanSecrets) {
      const findings = scanSecrets(text);
      if (findings.length > 0) {
        log(
          `inbound_claim: secrets detected in inbound message from ${event.senderUsername ?? event.senderId ?? "?"} on ${event.channel}: ` +
            findings.map((f) => f.label).join(", "),
        );
        if (cfg.redactSecrets) {
          const { text: cleaned } = redactSecrets(text);
          // Mutate the event-derived view used downstream. The host's
          // contract permits redaction by writing back through `event` only
          // for fields the host promises to re-read; for the rest we rely on
          // logs + downstream `before_prompt_build` to enforce.
          (event as { bodyForAgent?: string }).bodyForAgent = cleaned;
        }
      }
    }

    if (cfg.scanInjection) {
      const findings = scanInjection(text);
      if (findings.length > 0) {
        log(
          `inbound_claim: prompt-injection patterns in message from ${event.senderUsername ?? event.senderId ?? "?"}: ` +
            findings.slice(0, 3).map((f) => f.match).join(" | "),
        );
        if (cfg.blockOnInjection) {
          return {
            handled: true,
            reply: {
              kind: "text",
              text:
                "openclaw-os: This message looks like a prompt-injection attempt and was blocked. " +
                "If you believe this is wrong, contact the operator.",
            },
          } as PluginHookInboundClaimResult;
        }
      }
    }
  };
}
