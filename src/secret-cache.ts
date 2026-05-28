// AES-encrypted on-disk secret cache.
//
// Resolves `op://...` paths via the 1Password CLI (`op read`) with optional
// env-var fallback, and caches the result on disk encrypted with AES-256-CBC
// (PBKDF2 key derivation, per-user random salt) so the user isn't Touch-ID-
// prompted on every fetch.
//
// Threat model:
//   - On macOS (default), the passphrase that derives the AES key lives in
//     the user's Keychain (service: openclaw-shield) — NOT alongside the
//     cache. An attacker with read access to the cache dir but no Keychain
//     access cannot decrypt anything. See `src/keychain.ts` for details and
//     for the wallet-grade strict-ACL escape hatch.
//   - On non-darwin or with OPENCLAW_SHIELD_PASSPHRASE_BACKEND=file, the
//     passphrase falls back to a .salt file inside the cache dir. That is
//     obfuscation against backup scanners only, not encryption against an
//     attacker with read access to the user's home directory.
//
// Defaults:
//   - cache dir: $TMPDIR/.openclaw-shield-cache.<uid>/   (mode 0700)
//   - TTL:       3h (10800s) — override with OPENCLAW_SHIELD_SECRET_TTL
//   - bypass:    OPENCLAW_SHIELD_NO_CACHE=1
//   - cache dir override: OPENCLAW_SHIELD_CACHE_DIR=<path>  (Docker / nix:
//       point at a mounted volume so cache survives container restart and
//       doesn't sit in the container's ephemeral /tmp layer)
//
// Usage:
//   import { secret, clearSecretCache } from "./secret-cache.js";
//   const token = await secret("op://<vault>/<item>/<field>", { envFallback: "FOO_TOKEN" });

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import {
  createCipheriv,
  createDecipheriv,
  pbkdf2Sync,
  randomBytes,
} from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { getKeychainPassphrase } from "./keychain.js";

const execFileP = promisify(execFile);

// OpenSSL-compatible AES-256-CBC + PBKDF2-SHA256, salt prefix "Salted__"
// (the "openssl enc" file format). Lets the cache file be inspectable with
// `openssl enc -d -aes-256-cbc -pbkdf2 -pass pass:<salt>` if needed.
const MAGIC = Buffer.from("Salted__", "ascii");
const SALT_LEN = 8;
const KEY_LEN = 32;
const IV_LEN = 16;
const PBKDF2_ITERS = 10_000;

function deriveKeyIv(passphrase: string, salt: Buffer): { key: Buffer; iv: Buffer } {
  const out = pbkdf2Sync(passphrase, salt, PBKDF2_ITERS, KEY_LEN + IV_LEN, "sha256");
  return { key: out.subarray(0, KEY_LEN), iv: out.subarray(KEY_LEN) };
}

function encrypt(plaintext: string, passphrase: string): Buffer {
  const salt = randomBytes(SALT_LEN);
  const { key, iv } = deriveKeyIv(passphrase, salt);
  // AES-256-CBC + random IV per write is chosen for openssl `enc -aes-256-cbc
  // -pbkdf2` file-format compatibility; the cache stays inspectable from the
  // shell. Threat model is obfuscation against backup scanners — full GCM/AEAD
  // is unnecessary here (see module-level comment on threat model).
  const cipher = createCipheriv("aes-256-cbc", key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return Buffer.concat([MAGIC, salt, enc]);
}

function decrypt(blob: Buffer, passphrase: string): string {
  if (blob.length <= MAGIC.length + SALT_LEN) throw new Error("cache too short");
  if (!blob.subarray(0, MAGIC.length).equals(MAGIC)) throw new Error("bad magic");
  const salt = blob.subarray(MAGIC.length, MAGIC.length + SALT_LEN);
  const ciphertext = blob.subarray(MAGIC.length + SALT_LEN);
  const { key, iv } = deriveKeyIv(passphrase, salt);
  const decipher = createDecipheriv("aes-256-cbc", key, iv);
  const dec = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return dec.toString("utf8");
}

function cacheDir(): string {
  const override = process.env.OPENCLAW_SHIELD_CACHE_DIR;
  if (override) return override;
  const uid = typeof process.getuid === "function" ? process.getuid() : "x";
  return join(tmpdir(), `.openclaw-shield-cache.${uid}`);
}

function ttlSeconds(): number {
  const raw = process.env.OPENCLAW_SHIELD_SECRET_TTL;
  const n = raw ? Number.parseInt(raw, 10) : Number.NaN;
  return Number.isFinite(n) && n > 0 ? n : 10_800; // 3h
}

function cacheDisabled(): boolean {
  return process.env.OPENCLAW_SHIELD_NO_CACHE === "1";
}

function cacheKey(opPath: string): string {
  return opPath.replace(/[/:.@ ]/g, "_");
}

function ensureDirAndSalt(dir: string): string | null {
  try {
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      chmodSync(dir, 0o700);
    }
  } catch {
    return null;
  }

  // Prefer the macOS Keychain when available — passphrase lives outside the
  // cache dir, so a reader of the dir can't decrypt anything. Falls back to
  // the file-based .salt model on non-darwin or when the user has opted out
  // via OPENCLAW_SHIELD_PASSPHRASE_BACKEND=file.
  const keychainPass = getKeychainPassphrase();
  if (keychainPass) return keychainPass;

  // File-backed fallback.
  try {
    const saltPath = join(dir, ".salt");
    if (!existsSync(saltPath)) {
      writeFileSync(saltPath, randomBytes(32).toString("hex"), { mode: 0o600 });
    }
    const salt = readFileSync(saltPath, "utf8").trim();
    return salt || null;
  } catch {
    return null;
  }
}

function pruneStale(dir: string, ttl: number): void {
  try {
    const cutoff = Date.now() - ttl * 1000;
    for (const name of readdirSync(dir)) {
      if (name === ".salt") continue;
      const p = join(dir, name);
      try {
        const st = statSync(p);
        if (st.mtimeMs < cutoff) unlinkSync(p);
      } catch {
        /* ignore */
      }
    }
  } catch {
    /* ignore */
  }
}

async function fetchFromOp(opPath: string): Promise<string | null> {
  // Test-only escape hatch: when set, skip invoking `op read` entirely so the
  // caller falls straight through to the env-fallback path. Tests use this to
  // avoid hanging on a Touch-ID-prompt-bearing local 1Password CLI.
  if (process.env.OPENCLAW_SHIELD_SKIP_OP === "1") return null;
  try {
    const { stdout } = await execFileP("op", ["read", opPath], { timeout: 30_000 });
    const tok = stdout.replace(/\n$/, "");
    return tok || null;
  } catch {
    return null;
  }
}

export type SecretOptions = {
  /** Env-var name to consult if `op read` fails or `op` isn't installed. */
  envFallback?: string;
  /** Override TTL for this call only (seconds). */
  ttl?: number;
  /** Bypass the cache for this call (always refetch + rewrite). */
  noCache?: boolean;
};

/**
 * Resolve a secret referenced by `op://...` path, with an optional env-var
 * fallback. Cache lookups + writes happen automatically unless disabled.
 *
 * Returns the secret string, or `null` if neither `op` nor the env fallback
 * produced a value.
 */
export async function secret(opPath: string, opts: SecretOptions = {}): Promise<string | null> {
  if (!opPath) return null;
  const disabled = opts.noCache || cacheDisabled();
  const ttl = opts.ttl ?? ttlSeconds();
  const dir = cacheDir();
  const file = join(dir, cacheKey(opPath));

  let pass: string | null = null;
  if (!disabled) {
    pass = ensureDirAndSalt(dir);
    if (pass) pruneStale(dir, ttl);
  }

  // Cache-hit path
  if (!disabled && pass && existsSync(file)) {
    try {
      const age = (Date.now() - statSync(file).mtimeMs) / 1000;
      if (age < ttl) {
        try {
          return decrypt(readFileSync(file), pass);
        } catch {
          unlinkSync(file); // corrupt → drop and refetch
        }
      } else {
        unlinkSync(file); // stale → drop and refetch
      }
    } catch {
      /* fall through to refetch */
    }
  }

  // Cache miss: op → env fallback.
  let tok = await fetchFromOp(opPath);
  if (!tok && opts.envFallback) {
    tok = process.env[opts.envFallback] ?? null;
    if (tok === "") tok = null;
  }
  if (!tok) return null;

  // Write-through.
  if (!disabled && pass) {
    try {
      const tmp = `${file}.${process.pid}`;
      writeFileSync(tmp, encrypt(tok, pass), { mode: 0o600 });
      renameSync(tmp, file); // atomic on the same filesystem
    } catch {
      /* cache write best-effort */
    }
  }

  return tok;
}

/** Wipe the entire secret cache (including .salt — next fetch generates a new salt). */
export function clearSecretCache(): void {
  const dir = cacheDir();
  try {
    rmSync(dir, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
}

/** Cache directory path. Exported for tests + `secret --clear` style tooling. */
export function getCacheDir(): string {
  return cacheDir();
}
