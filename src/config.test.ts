import { describe, expect, it } from "vitest";
import { DEFAULT_CONFIG, resolveConfig } from "./config.js";

describe("resolveConfig", () => {
  it("returns defaults for undefined / null / non-object input", () => {
    expect(resolveConfig(undefined)).toEqual(DEFAULT_CONFIG);
    expect(resolveConfig(null)).toEqual(DEFAULT_CONFIG);
    expect(resolveConfig(42)).toEqual(DEFAULT_CONFIG);
    expect(resolveConfig("string")).toEqual(DEFAULT_CONFIG);
  });

  it("merges partial section overrides without losing other defaults", () => {
    const out = resolveConfig({ inboundClaim: { blockOnInjection: true } });
    expect(out.inboundClaim.blockOnInjection).toBe(true);
    expect(out.inboundClaim.scanSecrets).toBe(DEFAULT_CONFIG.inboundClaim.scanSecrets);
    expect(out.beforeToolCall).toEqual(DEFAULT_CONFIG.beforeToolCall);
  });

  it("respects verboseLogging when boolean is given", () => {
    expect(resolveConfig({ verboseLogging: true }).verboseLogging).toBe(true);
    expect(resolveConfig({ verboseLogging: false }).verboseLogging).toBe(false);
  });

  it("ignores non-boolean verboseLogging values", () => {
    expect(resolveConfig({ verboseLogging: "yes" as unknown }).verboseLogging).toBe(
      DEFAULT_CONFIG.verboseLogging,
    );
  });
});
