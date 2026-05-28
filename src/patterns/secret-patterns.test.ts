import { describe, expect, it } from "vitest";
import { redactSecrets, scanSecrets } from "./secret-patterns.js";

describe("scanSecrets", () => {
  it("detects AWS access keys", () => {
    expect(scanSecrets("token = AKIAIOSFODNN7EXAMPLE").length).toBeGreaterThan(0);
  });

  it("detects GitHub PATs", () => {
    const tok = "ghp_" + "a".repeat(36);
    const found = scanSecrets(`export GH=${tok}`);
    expect(found.some((f) => f.label === "GitHub PAT")).toBe(true);
  });

  it("detects OpenAI and Anthropic keys", () => {
    expect(scanSecrets("OPENAI_API_KEY=sk-" + "a".repeat(40)).length).toBeGreaterThan(0);
    expect(
      scanSecrets("ANTHROPIC_API_KEY=sk-ant-" + "a".repeat(40)).some(
        (f) => f.label === "Anthropic API Key",
      ),
    ).toBe(true);
  });

  it("detects private-key headers", () => {
    expect(scanSecrets("-----BEGIN RSA PRIVATE KEY-----").length).toBeGreaterThan(0);
  });

  it("detects generic credential assignments", () => {
    expect(scanSecrets('api_key = "abcdefghijklmnopqrst"').length).toBeGreaterThan(0);
    expect(scanSecrets('password: "hunter22-secure"').length).toBeGreaterThan(0);
  });

  it("returns no findings on clean text", () => {
    expect(scanSecrets("hello world how are you").length).toBe(0);
    expect(scanSecrets("").length).toBe(0);
  });
});

describe("redactSecrets", () => {
  it("masks the matched value with first-4 / last-4", () => {
    const tok = "ghp_" + "a".repeat(32) + "bcde";
    const { text, findings } = redactSecrets(`token=${tok}`);
    expect(findings.length).toBeGreaterThan(0);
    expect(text).toContain("redacted");
    expect(text).not.toContain(tok);
    // Visible prefix + suffix in the redaction marker
    expect(text).toMatch(/ghp_.*…/);
  });

  it("is a no-op on clean text", () => {
    const out = redactSecrets("nothing to see here");
    expect(out.text).toBe("nothing to see here");
    expect(out.findings.length).toBe(0);
  });
});
