import { describe, expect, it, vi } from "vitest";
import { DEFAULT_CONFIG, resolveConfig } from "../config.js";
import { makeBeforePromptBuildHandler } from "./before-prompt-build.js";

type Event = { prompt?: string; messages?: unknown[] };

function run(config = DEFAULT_CONFIG, event: Event = {}) {
  const log = vi.fn();
  const handler = makeBeforePromptBuildHandler(config, log);
  const result = (handler as unknown as (e: Event) => unknown)(event);
  return { result, log };
}

describe("before_prompt_build handler", () => {
  it("appends refusal guidance when a secret is in the assembled prompt", () => {
    const tok = "ghp_" + "a".repeat(36);
    const { result, log } = run(DEFAULT_CONFIG, { prompt: `notes: ${tok}` });
    expect(result).toMatchObject({});
    expect((result as { appendSystemContext: string }).appendSystemContext).toMatch(/openclaw-os/);
    expect((result as { appendSystemContext: string }).appendSystemContext).toMatch(/refuse/i);
    expect(log).toHaveBeenCalled();
  });

  it("detects secrets in messages, not just the prompt", () => {
    const tok = "AKIAIOSFODNN7EXAMPLE";
    const { result } = run(DEFAULT_CONFIG, {
      prompt: "",
      messages: [
        { role: "user", content: "hi" },
        { role: "assistant", content: [{ text: `from memory: ${tok}` }] },
      ],
    });
    expect(result).toBeTruthy();
    expect((result as { appendSystemContext: string }).appendSystemContext).toMatch(/refuse/i);
  });

  it("is a no-op on clean context", () => {
    const { result, log } = run(DEFAULT_CONFIG, {
      prompt: "summarise the meeting notes",
      messages: [{ role: "user", content: "the customer asked about pricing" }],
    });
    expect(result).toBeUndefined();
    expect(log).not.toHaveBeenCalled();
  });

  it("is a no-op when scanAssembledPrompt is disabled", () => {
    const cfg = resolveConfig({ beforePromptBuild: { scanAssembledPrompt: false } });
    const { result } = run(cfg, { prompt: "token=" + "ghp_" + "a".repeat(36) });
    expect(result).toBeUndefined();
  });

  it("is a no-op on empty input", () => {
    const { result } = run(DEFAULT_CONFIG, { prompt: "", messages: [] });
    expect(result).toBeUndefined();
  });
});
