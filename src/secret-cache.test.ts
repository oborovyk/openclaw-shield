import { existsSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { clearSecretCache, getCacheDir, secret } from "./secret-cache.js";

const TEST_PATH = "op://openclaw-shield/test/" + Math.random().toString(36).slice(2);
const ENV_NAME = "OPENCLAW_SHIELD_TEST_TOKEN";

describe("secret cache", () => {
  beforeEach(() => {
    clearSecretCache();
    delete process.env.OPENCLAW_SHIELD_NO_CACHE;
    delete process.env[ENV_NAME];
  });

  afterEach(() => {
    clearSecretCache();
    delete process.env.OPENCLAW_SHIELD_NO_CACHE;
    delete process.env[ENV_NAME];
  });

  it("falls back to env var when op is unavailable", async () => {
    process.env[ENV_NAME] = "tok-via-env";
    const v = await secret(TEST_PATH, { envFallback: ENV_NAME });
    expect(v).toBe("tok-via-env");
  });

  it("returns null when neither op nor env var produce a value", async () => {
    const v = await secret(TEST_PATH, { envFallback: ENV_NAME });
    expect(v).toBeNull();
  });

  it("writes a cache file on successful resolve", async () => {
    process.env[ENV_NAME] = "tok-cached";
    await secret(TEST_PATH, { envFallback: ENV_NAME });
    const dir = getCacheDir();
    expect(existsSync(dir)).toBe(true);
    const files = readdirSync(dir).filter((f) => f !== ".salt");
    expect(files.length).toBe(1);
  });

  it("returns the cached value on a second call (env var removed)", async () => {
    process.env[ENV_NAME] = "tok-cached-then-gone";
    const first = await secret(TEST_PATH, { envFallback: ENV_NAME });
    delete process.env[ENV_NAME];
    const second = await secret(TEST_PATH, { envFallback: ENV_NAME });
    expect(second).toBe(first);
  });

  it("gracefully re-fetches when the cache file is corrupted", async () => {
    process.env[ENV_NAME] = "tok-then-corrupted";
    await secret(TEST_PATH, { envFallback: ENV_NAME });
    const dir = getCacheDir();
    const cacheFile = readdirSync(dir).find((f) => f !== ".salt");
    expect(cacheFile).toBeDefined();
    writeFileSync(join(dir, cacheFile as string), Buffer.from("garbage"));
    delete process.env[ENV_NAME];
    const v = await secret(TEST_PATH, { envFallback: ENV_NAME });
    expect(v).toBeNull();
  });

  it("does not write the cache when OPENCLAW_SHIELD_NO_CACHE=1", async () => {
    process.env.OPENCLAW_SHIELD_NO_CACHE = "1";
    process.env[ENV_NAME] = "tok-nocache";
    const v = await secret(TEST_PATH, { envFallback: ENV_NAME });
    expect(v).toBe("tok-nocache");
    expect(existsSync(getCacheDir())).toBe(false);
  });

  it("clearSecretCache removes the cache directory", async () => {
    process.env[ENV_NAME] = "tok-to-clear";
    await secret(TEST_PATH, { envFallback: ENV_NAME });
    expect(existsSync(getCacheDir())).toBe(true);
    clearSecretCache();
    expect(existsSync(getCacheDir())).toBe(false);
  });

  it("noCache opt bypasses cache for a single call", async () => {
    process.env[ENV_NAME] = "tok-once";
    const v = await secret(TEST_PATH, { envFallback: ENV_NAME, noCache: true });
    expect(v).toBe("tok-once");
    expect(existsSync(getCacheDir())).toBe(false);
  });

  it("returns null on empty opPath", async () => {
    expect(await secret("")).toBeNull();
  });
});
