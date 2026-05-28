import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { deleteKeychainPassphrase, getKeychainPassphrase } from "./keychain.js";

const isDarwin = process.platform === "darwin";

describe("keychain backend resolution", () => {
  beforeEach(() => {
    delete process.env.OPENCLAW_SHIELD_PASSPHRASE_BACKEND;
  });

  afterEach(() => {
    delete process.env.OPENCLAW_SHIELD_PASSPHRASE_BACKEND;
  });

  it("returns null when forced to file backend", () => {
    process.env.OPENCLAW_SHIELD_PASSPHRASE_BACKEND = "file";
    expect(getKeychainPassphrase()).toBeNull();
  });

  it.skipIf(isDarwin)("returns null on non-darwin in auto mode", () => {
    expect(getKeychainPassphrase()).toBeNull();
  });

  it.skipIf(isDarwin)("throws when keychain backend is forced on non-darwin", () => {
    process.env.OPENCLAW_SHIELD_PASSPHRASE_BACKEND = "keychain";
    expect(() => getKeychainPassphrase()).toThrow(/security.*CLI is unavailable/i);
  });
});

describe.skipIf(!isDarwin)("keychain (macOS)", () => {
  beforeEach(() => {
    delete process.env.OPENCLAW_SHIELD_PASSPHRASE_BACKEND;
    deleteKeychainPassphrase();
  });

  afterEach(() => {
    deleteKeychainPassphrase();
    delete process.env.OPENCLAW_SHIELD_PASSPHRASE_BACKEND;
  });

  it("creates a 64-hex-char passphrase on first call", () => {
    const p = getKeychainPassphrase();
    expect(p).toMatch(/^[0-9a-f]{64}$/);
  });

  it("returns the same passphrase on subsequent calls", () => {
    const a = getKeychainPassphrase();
    const b = getKeychainPassphrase();
    expect(a).toBe(b);
  });

  it("regenerates after deleteKeychainPassphrase()", () => {
    const a = getKeychainPassphrase();
    deleteKeychainPassphrase();
    const b = getKeychainPassphrase();
    expect(a).not.toBe(b);
  });
});
