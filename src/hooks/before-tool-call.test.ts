import { describe, expect, it, vi } from "vitest";
import { DEFAULT_CONFIG } from "../config.js";
import { makeBeforeToolCallHandler } from "./before-tool-call.js";

// Plain shape mirroring openclaw's PluginHookBeforeToolCallEvent — keeps the
// test file free of host-monorepo type imports.
type Event = { toolName: string; params: Record<string, unknown> };

function run(event: Event) {
  const log = vi.fn();
  const handler = makeBeforeToolCallHandler(DEFAULT_CONFIG, log);
  // The handler also takes a `ctx` arg per the openclaw signature; we don't
  // use it inside the handler so passing `undefined` (via `as any`) is fine.
  const result = (handler as unknown as (e: Event) => unknown)(event);
  return { result, log };
}

describe("before_tool_call handler", () => {
  it("blocks rm -rf / on the bash tool", () => {
    const { result } = run({ toolName: "bash", params: { command: "rm -rf /" } });
    expect(result).toMatchObject({ block: true });
    expect((result as { blockReason: string }).blockReason).toMatch(/destruction-scan/);
  });

  it("blocks git force-push to main on the exec tool", () => {
    const { result } = run({
      toolName: "exec",
      params: { command: "git push --force origin main" },
    });
    expect(result).toMatchObject({ block: true });
  });

  it("does not block safe commands on bash", () => {
    const { result } = run({ toolName: "bash", params: { command: "ls -la" } });
    expect(result).toBeUndefined();
  });

  it("does not invoke destruction-scan on non-shell tools", () => {
    // `read` accepts a path param but is not a shell tool — `rm -rf /` as a
    // path-string should not trip the destruction rules.
    const { result } = run({ toolName: "read", params: { path: "/etc/hosts" } });
    expect(result).toBeUndefined();
  });

  it("blocks when a credential appears in any string param", () => {
    const tok = "ghp_" + "a".repeat(36);
    const { result } = run({
      toolName: "http",
      params: { headers: { Authorization: `Bearer ${tok}` } },
    });
    expect(result).toMatchObject({ block: true });
    expect((result as { blockReason: string }).blockReason).toMatch(/secret-scan/);
  });

  it("allows tools with no string params", () => {
    const { result } = run({ toolName: "noop", params: { count: 1, ok: true } });
    expect(result).toBeUndefined();
  });
});
