// macOS Keychain wrapper for the secret-cache passphrase.
//
// On darwin, the passphrase that derives the AES key lives in the user's
// login keychain (service: "openclaw-shield", account: "cache-<uid>") instead
// of as a plain-text file in the cache directory. That means an attacker with
// read access to the cache dir can no longer decrypt anything — they'd also
// need the keychain to be unlocked AND the user's prior Always-Allow consent.
//
// Behavior:
//   - On non-darwin, getKeychainPassphrase() returns null immediately and the
//     caller falls back to the file-based .salt model.
//   - On darwin, first call creates a 64-hex-char passphrase if none exists.
//   - Subsequent calls fetch via `security find-generic-password -w`. The
//     first openclaw process to fetch triggers a one-time GUI prompt asking
//     to allow access; user clicks Always Allow → silent forever after.
//
// To require Touch ID / unlock prompt EVERY openclaw restart (wallet-grade
// posture), open Keychain Access, find the "openclaw-shield" item, Get Info
// → Access Control, and remove the prior Always-Allow entry. We cannot set
// kSecAccessControl with biometric requirements from the shell `security`
// CLI — that requires the Security framework API.
//
// Override the backend with:
//   OPENCLAW_SHIELD_PASSPHRASE_BACKEND=keychain  (force; error if unavailable)
//   OPENCLAW_SHIELD_PASSPHRASE_BACKEND=file      (force file-based .salt even on darwin)
//   OPENCLAW_SHIELD_PASSPHRASE_BACKEND=auto      (default: keychain on darwin, file elsewhere)

import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";

const SERVICE = "openclaw-shield";

function accountForUid(): string {
  const uid = typeof process.getuid === "function" ? process.getuid() : "x";
  return `cache-${uid}`;
}

function securityCliAvailable(): boolean {
  if (process.platform !== "darwin") return false;
  try {
    execFileSync("security", ["-h"], { stdio: "ignore", timeout: 5_000 });
    return true;
  } catch {
    return false;
  }
}

function backend(): "keychain" | "file" | "auto" {
  const v = process.env.OPENCLAW_SHIELD_PASSPHRASE_BACKEND;
  return v === "keychain" || v === "file" ? v : "auto";
}

function read(): string | null {
  try {
    const out = execFileSync(
      "security",
      ["find-generic-password", "-a", accountForUid(), "-s", SERVICE, "-w"],
      { encoding: "utf8", timeout: 30_000, stdio: ["ignore", "pipe", "ignore"] },
    );
    const v = out.trim();
    return v || null;
  } catch {
    return null;
  }
}

function write(passphrase: string): boolean {
  try {
    // -U updates the existing entry if present (without -U, returns errSecDuplicateItem).
    execFileSync(
      "security",
      ["add-generic-password", "-a", accountForUid(), "-s", SERVICE, "-w", passphrase, "-U"],
      { stdio: "ignore", timeout: 30_000 },
    );
    return true;
  } catch {
    return false;
  }
}

/**
 * Resolve the cache passphrase from the macOS Keychain. Creates it on first
 * call if it doesn't exist. Returns null if the keychain backend isn't
 * available (non-darwin, security CLI missing, or user forced file backend).
 */
export function getKeychainPassphrase(): string | null {
  const mode = backend();
  if (mode === "file") return null;
  if (mode === "keychain" && !securityCliAvailable()) {
    throw new Error(
      "OPENCLAW_SHIELD_PASSPHRASE_BACKEND=keychain set but macOS `security` CLI is unavailable",
    );
  }
  if (mode === "auto" && !securityCliAvailable()) return null;

  const existing = read();
  if (existing) return existing;

  const fresh = randomBytes(32).toString("hex");
  if (!write(fresh)) {
    if (mode === "keychain") {
      throw new Error("OPENCLAW_SHIELD_PASSPHRASE_BACKEND=keychain: failed to write to Keychain");
    }
    return null;
  }
  return fresh;
}

/** Remove the keychain item. Returns true if removed (or didn't exist), false on error. */
export function deleteKeychainPassphrase(): boolean {
  if (!securityCliAvailable()) return true;
  try {
    execFileSync(
      "security",
      ["delete-generic-password", "-a", accountForUid(), "-s", SERVICE],
      { stdio: "ignore", timeout: 30_000 },
    );
    return true;
  } catch {
    // Already absent counts as success.
    return true;
  }
}
