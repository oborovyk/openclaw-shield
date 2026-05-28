import { describe, expect, it, vi } from "vitest";
import { DEFAULT_CONFIG, resolveConfig } from "../config.js";
import { makeBeforeDispatchHandler } from "./before-dispatch.js";

type Event = {
  content: string;
  body?: string;
  channel?: string;
  sessionKey?: string;
};

function run(config = DEFAULT_CONFIG, event: Event) {
  const log = vi.fn();
  const handler = makeBeforeDispatchHandler(config, log);
  const result = (handler as unknown as (e: Event) => unknown)(event);
  return { result, log };
}

describe("before_dispatch handler", () => {
  it("rewrites the body with redacted secrets", () => {
    const tok = "ghp_" + "a".repeat(36);
    const { result, log } = run(DEFAULT_CONFIG, { content: `token=${tok}`, body: `token=${tok}` });
    expect(result).toMatchObject({ handled: false });
    expect((result as { text: string }).text).toContain("redacted");
    expect((result as { text: string }).text).not.toContain(tok);
    expect(log).toHaveBeenCalled();
  });

  it("is a no-op when redactSecrets is disabled", () => {
    const cfg = resolveConfig({ inboundClaim: { redactSecrets: false } });
    const { result } = run(cfg, { content: `token=ghp_${"a".repeat(36)}` });
    expect(result).toBeUndefined();
  });

  it("is a no-op on clean text", () => {
    const { result } = run(DEFAULT_CONFIG, { content: "hello there", body: "hello there" });
    expect(result).toBeUndefined();
  });
});
