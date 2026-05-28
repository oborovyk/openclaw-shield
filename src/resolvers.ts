// Per-vendor secret-resolver subprocess wrappers.
//
// Each resolveX function takes a reference string and returns the plaintext
// value (or null on failure). The RESOLVERS map keys URL prefix → function;
// resolve() dispatches by prefix.
//
// Supported reference shapes:
//
//   op://<vault>/<item>/<field>           1Password (op read)
//   bws://<secret-id>                     Bitwarden Secrets Mgr (bws secret get)
//   doppler://<project>/<config>/<key>    Doppler (doppler secrets get)
//   infisical://<env>/<key>               Infisical (infisical secrets get)
//   vault://<path>/<field>                HashiCorp Vault (vault kv get -field=)
//   pass://<name>                         Unix password store (pass show)
//   keychain://<account>@<service>        macOS Keychain (security find-generic-password)
//   aws-sm://<name>                       AWS Secrets Manager
//
// Test-only escape hatch: OPENCLAW_SHIELD_SKIP_CLI=1 makes every resolver
// return null. OPENCLAW_SHIELD_SKIP_OP=1 (back-compat) is still honoured.

import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileP = promisify(execFile);

type Resolver = (ref: string) => Promise<string | null>;

function cliSkipped(): boolean {
  return (
    process.env.OPENCLAW_SHIELD_SKIP_CLI === "1" ||
    process.env.OPENCLAW_SHIELD_SKIP_OP === "1"
  );
}

async function run(argv: string[]): Promise<string | null> {
  if (cliSkipped()) return null;
  try {
    const { stdout } = await execFileP(argv[0], argv.slice(1), { timeout: 30_000 });
    const v = stdout.replace(/\n$/, "");
    return v || null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Per-vendor resolvers
// ---------------------------------------------------------------------------

export const resolve1Password: Resolver = (ref) => run(["op", "read", ref]);

export const resolveBitwarden: Resolver = async (ref) => {
  const id = ref.slice("bws://".length);
  if (!id) return null;
  const raw = await run(["bws", "secret", "get", id, "--output", "json"]);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as { value?: unknown };
    return typeof parsed.value === "string" && parsed.value ? parsed.value : null;
  } catch {
    return null;
  }
};

export const resolveDoppler: Resolver = (ref) => {
  const path = ref.slice("doppler://".length);
  const parts = path.split("/");
  if (parts.length !== 3) return Promise.resolve(null);
  const [project, config, key] = parts;
  return run([
    "doppler", "secrets", "get", key,
    "--project", project, "--config", config, "--plain",
  ]);
};

export const resolveInfisical: Resolver = (ref) => {
  const path = ref.slice("infisical://".length);
  const slash = path.indexOf("/");
  if (slash <= 0 || slash === path.length - 1) return Promise.resolve(null);
  const env = path.slice(0, slash);
  const key = path.slice(slash + 1);
  return run(["infisical", "secrets", "get", key, `--env=${env}`, "--plain"]);
};

export const resolveVault: Resolver = (ref) => {
  const path = ref.slice("vault://".length);
  const lastSlash = path.lastIndexOf("/");
  if (lastSlash <= 0 || lastSlash === path.length - 1) return Promise.resolve(null);
  const kvPath = path.slice(0, lastSlash);
  const field = path.slice(lastSlash + 1);
  return run(["vault", "kv", "get", `-field=${field}`, kvPath]);
};

export const resolvePass: Resolver = (ref) => {
  const name = ref.slice("pass://".length);
  if (!name) return Promise.resolve(null);
  return run(["pass", "show", name]);
};

export const resolveKeychain: Resolver = (ref) => {
  const pair = ref.slice("keychain://".length);
  const at = pair.indexOf("@");
  if (at <= 0 || at === pair.length - 1) return Promise.resolve(null);
  const account = pair.slice(0, at);
  const service = pair.slice(at + 1);
  return run(["security", "find-generic-password", "-a", account, "-s", service, "-w"]);
};

export const resolveAwsSm: Resolver = (ref) => {
  const name = ref.slice("aws-sm://".length);
  if (!name) return Promise.resolve(null);
  return run([
    "aws", "secretsmanager", "get-secret-value",
    "--secret-id", name,
    "--query", "SecretString",
    "--output", "text",
  ]);
};

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

export const RESOLVERS: Array<[string, Resolver]> = [
  ["op://", resolve1Password],
  ["bws://", resolveBitwarden],
  ["doppler://", resolveDoppler],
  ["infisical://", resolveInfisical],
  ["vault://", resolveVault],
  ["pass://", resolvePass],
  ["keychain://", resolveKeychain],
  ["aws-sm://", resolveAwsSm],
];

export async function resolve(ref: string): Promise<string | null> {
  if (!ref) return null;
  for (const [prefix, fn] of RESOLVERS) {
    if (ref.startsWith(prefix)) return fn(ref);
  }
  return null;
}
