import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/**/*.test.ts"],
    environment: "node",
    // On machines where the 1Password CLI (`op`) is installed and unlocked,
    // each first-call to `secret(...)` spawns `op read` which may prompt for
    // Touch ID and take several seconds. Tests in CI run without `op` so the
    // call fails fast; bump the default so dev runs aren't flaky.
    testTimeout: 15_000,
  },
});
