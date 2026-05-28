// Resolved guardrail config — fields populated from the plugin's configSchema
// (declared in openclaw.plugin.json) with safe defaults applied.

export type GuardrailsConfig = {
  inboundClaim: {
    scanSecrets: boolean;
    scanInjection: boolean;
    redactSecrets: boolean;
    blockOnInjection: boolean;
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
  beforeToolCall?: Partial<GuardrailsConfig["beforeToolCall"]>;
  afterToolCall?: Partial<GuardrailsConfig["afterToolCall"]>;
  verboseLogging?: boolean;
};

export function resolveConfig(raw: unknown): GuardrailsConfig {
  if (!raw || typeof raw !== "object") return DEFAULT_CONFIG;
  const r = raw as RawConfig;
  return {
    inboundClaim: { ...DEFAULT_CONFIG.inboundClaim, ...r.inboundClaim },
    beforeToolCall: { ...DEFAULT_CONFIG.beforeToolCall, ...r.beforeToolCall },
    afterToolCall: { ...DEFAULT_CONFIG.afterToolCall, ...r.afterToolCall },
    verboseLogging:
      typeof r.verboseLogging === "boolean" ? r.verboseLogging : DEFAULT_CONFIG.verboseLogging,
  };
}
