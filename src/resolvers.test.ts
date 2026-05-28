import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { RESOLVERS, resolve } from "./resolvers.js";

// We don't invoke real CLIs here (would require every manager installed).
// We verify the prefix → resolver mapping, malformed-ref handling, and the
// SKIP_CLI / SKIP_OP escape hatches.

beforeEach(() => {
  process.env.OPENCLAW_SHIELD_SKIP_CLI = "1";
  delete process.env.OPENCLAW_SHIELD_SKIP_OP;
});

afterEach(() => {
  delete process.env.OPENCLAW_SHIELD_SKIP_CLI;
  delete process.env.OPENCLAW_SHIELD_SKIP_OP;
});

describe("resolve() dispatch", () => {
  it.each([
    ["op://vault/item/field"],
    ["bws://abc-123-def"],
    ["doppler://my-proj/dev/STRIPE_KEY"],
    ["infisical://dev/STRIPE_KEY"],
    ["vault://kv/foo/password"],
    ["pass://github/oborovyk"],
    ["keychain://oleg@openclaw-shield"],
    ["aws-sm://stripe/prod-key"],
  ])("finds a matching prefix for %s", (ref) => {
    const match = RESOLVERS.find(([prefix]) => ref.startsWith(prefix));
    expect(match).toBeDefined();
  });

  it("returns null on an unknown prefix", async () => {
    expect(await resolve("unknown://foo")).toBeNull();
    expect(await resolve("ftp://example.com/file")).toBeNull();
    expect(await resolve("foo")).toBeNull();
  });

  it("returns null on an empty reference", async () => {
    expect(await resolve("")).toBeNull();
  });
});

describe("SKIP env vars short-circuit", () => {
  it.each([
    ["op://v/i/f"],
    ["bws://abc"],
    ["doppler://p/c/k"],
    ["infisical://dev/k"],
    ["vault://kv/foo/bar"],
    ["pass://name"],
    ["keychain://a@b"],
    ["aws-sm://name"],
  ])("SKIP_CLI=1 returns null for %s", async (ref) => {
    expect(await resolve(ref)).toBeNull();
  });

  it("SKIP_OP=1 back-compat still short-circuits", async () => {
    delete process.env.OPENCLAW_SHIELD_SKIP_CLI;
    process.env.OPENCLAW_SHIELD_SKIP_OP = "1";
    expect(await resolve("op://v/i/f")).toBeNull();
    expect(await resolve("vault://kv/foo/bar")).toBeNull();
  });
});

describe("malformed references", () => {
  beforeEach(() => {
    delete process.env.OPENCLAW_SHIELD_SKIP_CLI;
  });

  it.each([
    ["bws://"],
    ["doppler://just-project"],
    ["doppler://proj/config"],
    ["infisical://dev"],
    ["vault://no-field-suffix"],
    ["vault://path-with-trailing/"],
    ["pass://"],
    ["keychain://no-at-sign"],
    ["keychain://@service"],
    ["keychain://acc@"],
    ["aws-sm://"],
  ])("malformed %s returns null without invoking subprocess", async (ref) => {
    expect(await resolve(ref)).toBeNull();
  });
});
