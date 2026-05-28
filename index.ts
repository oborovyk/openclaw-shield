// openclaw-os Security — plugin entry point.
//
// Registers five runtime hooks on OpenClaw:
//   - inbound_claim       → secret + prompt-injection scan on inbound channel messages (warn / opt-in block)
//   - before_dispatch     → redact secrets in the body the agent will see (text rewrite)
//   - before_prompt_build → late-binding scan of the assembled prompt; appends refusal guidance if a secret slipped in via memory/skills
//   - before_tool_call    → destruction guard + secret scan on tool params (block)
//   - after_tool_call     → secret + injection scan on tool output (warn-only)
//
// Configured via plugins.entries["openclaw-os"] in openclaw config; see
// `openclaw.plugin.json` for the schema and `src/config.ts` for the defaults.

import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { resolveConfig } from "./src/config.js";
import { makeAfterToolCallHandler } from "./src/hooks/after-tool-call.js";
import { makeBeforeDispatchHandler } from "./src/hooks/before-dispatch.js";
import { makeBeforePromptBuildHandler } from "./src/hooks/before-prompt-build.js";
import { makeBeforeToolCallHandler } from "./src/hooks/before-tool-call.js";
import { makeInboundClaimHandler } from "./src/hooks/inbound-claim.js";

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
    api.registerHook("before_dispatch", makeBeforeDispatchHandler(config, log), {
      name: "openclaw-os/before-dispatch",
    });
    api.registerHook("before_prompt_build", makeBeforePromptBuildHandler(config, log), {
      name: "openclaw-os/before-prompt-build",
    });
    api.registerHook("before_tool_call", makeBeforeToolCallHandler(config, log), {
      name: "openclaw-os/before-tool-call",
    });
    api.registerHook("after_tool_call", makeAfterToolCallHandler(config, log), {
      name: "openclaw-os/after-tool-call",
    });
  },
});
