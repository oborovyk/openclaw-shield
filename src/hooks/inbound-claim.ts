// inbound_claim hook — runs once per claimed inbound channel message (Telegram,
// WhatsApp, …). The event passed in is a COPY of the host's hookContext (see
// openclaw/src/hooks/message-hook-mappers.ts:319), so mutating event.bodyForAgent
// does NOT affect what the model sees. This hook is therefore warn/block-only;
// actual redaction lives in before-dispatch.ts where the result type permits a
// text rewrite.
//
// Behavior:
//   (a) scan for credentials → log
//   (b) scan for prompt-injection patterns → log + opt-in hard-block via reply
//
// Hard-blocking is off by default — false-positive risk on chat text is high.
// Enable via config: inboundClaim.blockOnInjection = true.

import type {
  PluginHookInboundClaimEvent,
  PluginHookInboundClaimResult,
} from "openclaw/plugins/hook-message.types";
import { scanInjection } from "../patterns/injection-patterns.js";
import { scanSecrets } from "../patterns/secret-patterns.js";
import type { GuardrailsConfig } from "../config.js";

const BLOCK_REPLY_TEXT =
  "openclaw-shield: This message looks like a prompt-injection attempt and was blocked. " +
  "If you believe this is wrong, contact the operator.";

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
    const senderTag = event.senderUsername ?? event.senderId ?? "?";

    if (cfg.scanSecrets) {
      const findings = scanSecrets(text);
      if (findings.length > 0) {
        log(
          `inbound_claim: secrets detected in inbound message from ${senderTag} on ${event.channel}: ` +
            findings.map((f) => f.label).join(", "),
        );
      }
    }

    if (cfg.scanInjection) {
      const findings = scanInjection(text);
      if (findings.length > 0) {
        log(
          `inbound_claim: prompt-injection patterns in message from ${senderTag}: ` +
            findings.slice(0, 3).map((f) => f.match).join(" | "),
        );
        if (cfg.blockOnInjection) {
          return {
            handled: true,
            reply: { kind: "text", text: BLOCK_REPLY_TEXT },
          } as PluginHookInboundClaimResult;
        }
      }
    }
  };
}
