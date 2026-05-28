// Resolved guardrail config — fields populated from the plugin's configSchema
// (declared in openclaw.plugin.json) with safe defaults applied.

export type GuardrailsConfig = {
  inboundClaim: {
    scanSecrets: boolean;
    scanInjection: boolean;
    redactSecrets: boolean;
    blockOnInjection: boolean;
  };
  beforePromptBuild: {
    scanAssembledPrompt: boolean;
  };
  beforeToolCall: {
    destruction: boolean;
    scanParamSecrets: boolean;
  };
  afterToolCall: {
    scanReadResultsForInjection: boolean;
    scanShellOutputForSecrets: boolean;
  };
  verboseLogging: boolean;
};

export const DEFAULT_CONFIG: GuardrailsConfig = {
  inboundClaim: {
    scanSecrets: true,
    scanInjection: true,
    redactSecrets: true,
    blockOnInjection: false, // false-positive risk on chat → warn-only by default
  },
  beforePromptBuild: {
    scanAssembledPrompt: true,
  },
  beforeToolCall: {
    destruction: true,
    scanParamSecrets: true,
  },
  afterToolCall: {
    scanReadResultsForInjection: true,
    scanShellOutputForSecrets: true,
  },
  verboseLogging: false,
};

type RawConfig = {
  inboundClaim?: Partial<GuardrailsConfig["inboundClaim"]>;
  beforePromptBuild?: Partial<GuardrailsConfig["beforePromptBuild"]>;
  beforeToolCall?: Partial<GuardrailsConfig["beforeToolCall"]>;
  afterToolCall?: Partial<GuardrailsConfig["afterToolCall"]>;
  verboseLogging?: boolean;
};

export function resolveConfig(raw: unknown): GuardrailsConfig {
  if (!raw || typeof raw !== "object") return DEFAULT_CONFIG;
  const r = raw as RawConfig;
  return {
    inboundClaim: { ...DEFAULT_CONFIG.inboundClaim, ...r.inboundClaim },
    beforePromptBuild: { ...DEFAULT_CONFIG.beforePromptBuild, ...r.beforePromptBuild },
    beforeToolCall: { ...DEFAULT_CONFIG.beforeToolCall, ...r.beforeToolCall },
    afterToolCall: { ...DEFAULT_CONFIG.afterToolCall, ...r.afterToolCall },
    verboseLogging:
      typeof r.verboseLogging === "boolean" ? r.verboseLogging : DEFAULT_CONFIG.verboseLogging,
  };
}
