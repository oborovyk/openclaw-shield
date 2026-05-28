// openclaw-os Security — plugin entry point.
//
// Registers three runtime hooks on OpenClaw:
//   - inbound_claim     → secret + prompt-injection scan on inbound channel messages
//   - before_tool_call  → destruction guard + secret scan on tool params
//   - after_tool_call   → secret + injection scan on tool output (warn-only)
//
// Configured via plugins.entries["openclaw-os"] in openclaw config; see
// `openclaw.plugin.json` for the schema and `src/config.ts` for the defaults.

import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { resolveConfig } from "./src/config.js";
import { makeInboundClaimHandler } from "./src/hooks/inbound-claim.js";
import { makeBeforeToolCallHandler } from "./src/hooks/before-tool-call.js";
import { makeAfterToolCallHandler } from "./src/hooks/after-tool-call.js";

export default definePluginEntry({
  id: "openclaw-os",
  name: "openclaw-os Security",
  description:
    "Runtime security guardrails for OpenClaw: secret scan, prompt-injection scan, destruction guard, read-injection, bash-output scan.",
  kind: "security",
  register(api) {
    const config = resolveConfig((api as { pluginConfig?: unknown }).pluginConfig);
    const log = (line: string): void => {
      // Security findings are low-volume and high-value; we always log.
      // verboseLogging is retained on the config schema for future use
      // (per-handler diagnostic traces) but is intentionally not gated here.
      // eslint-disable-next-line no-console
      console.warn(`[openclaw-os] ${line}`);
    };

    api.registerHook("inbound_claim", makeInboundClaimHandler(config, log), {
      name: "openclaw-os/inbound-claim",
    });
    api.registerHook("before_tool_call", makeBeforeToolCallHandler(config, log), {
      name: "openclaw-os/before-tool-call",
    });
    api.registerHook("after_tool_call", makeAfterToolCallHandler(config, log), {
      name: "openclaw-os/after-tool-call",
    });
  },
});
