---
name: secret-handoff
description: Use a secret manager (1Password, Bitwarden, Doppler, Infisical, HashiCorp Vault, pass, macOS Keychain, AWS Secrets Manager) instead of plaintext when handling credentials in either direction. Trigger when (a) writing a credential to a .env / config / secrets file, (b) needing a credential to call an API or run a command, (c) the user mentions API keys, tokens, secrets, .env, op://, bws://, doppler, infisical, vault, 1Password, Bitwarden, or (d) openclaw-shield blocks a write because the content matched a credential pattern.
---

# secret-handoff

Never put a literal credential into a file Claude writes, and never paste a literal credential into the conversation when the user can store it in a secret manager instead. Every modern secret manager gives you a way to (a) store the value once and (b) inject it into the app's environment at run time. Use that path.

## Step 0: which manager does the project use?

If you don't already know, ASK the user:

> "Where do you keep secrets — 1Password, Bitwarden, Doppler, Infisical, HashiCorp Vault, or something else?"

Then check the relevant CLI is available before proceeding:

```bash
op --version          # 1Password
bws --version         # Bitwarden Secrets Manager
doppler --version
infisical --version
vault --version       # HashiCorp Vault
pass --version
aws --version         # AWS (for Secrets Manager)
```

If the CLI is missing, tell the user **the exact install command** from this table — don't improvise from memory or web-search:

| Manager | macOS | Linux | Windows | Docs |
| --- | --- | --- | --- | --- |
| 1Password (`op`) | `brew install 1password-cli` | per distro (see docs) | `winget install 1password-cli` | https://developer.1password.com/docs/cli/get-started |
| Bitwarden Secrets Mgr (`bws`) | `brew install bitwarden-sm` | release binary from GitHub | release binary from GitHub | https://bitwarden.com/help/secrets-manager-cli |
| Doppler | `brew install dopplerhq/cli/doppler` | `curl -Ls https://cli.doppler.com/install.sh \| sh` | `scoop install doppler` | https://docs.doppler.com/docs/install-cli |
| Infisical | `brew install infisical/get-cli/infisical` | `curl -1sLf 'https://dl.cloudsmith.io/public/infisical/infisical-cli/setup.deb.sh' \| sudo -E bash` | `scoop install infisical` | https://infisical.com/docs/cli/overview |
| HashiCorp Vault | `brew install hashicorp/tap/vault` | per distro (see docs) | `choco install vault` | https://developer.hashicorp.com/vault/docs/install |
| `pass` | `brew install pass` | `apt install pass` / `dnf install pass` | WSL only | https://www.passwordstore.org |
| AWS CLI | `brew install awscli` | `pip install awscli` / per distro | MSI installer | https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html |
| macOS Keychain (`security`) | preinstalled | n/a | n/a | `man security` |

Don't silently write literal secrets just because the tool isn't there.

## Command discipline

The recipes below are **the** commands to use. Do not paraphrase, do not substitute "similar-looking" flags, do not improvise variants you saw in a different project. If the user's manager isn't covered by a recipe below, ASK before running anything against an unfamiliar CLI — the surface for accidentally exposing a value is too large.

Quick-reference for store + read across all managers:

| Manager | Store | Read |
| --- | --- | --- |
| 1Password | `op item create --category="API Credential" --vault="<v>" --title="<t>" credential="<value>"` | `op read op://<v>/<t>/credential` |
| Bitwarden SM | `bws secret create <key> "<value>" <project-id>` | `bws secret get <id>` |
| Doppler | `doppler secrets set <KEY>="<value>" --project=<p> --config=<env>` | `doppler secrets get <KEY> --plain` |
| Infisical | `infisical secrets set <KEY>="<value>"` | `infisical secrets get <KEY> --plain` |
| HashiCorp Vault | `vault kv put secret/<path> <key>="<value>"` | `vault kv get -field=<key> secret/<path>` |
| `pass` | `echo "<value>" \| pass insert -m <name>` | `pass show <name>` |
| macOS Keychain | `security add-generic-password -a "<account>" -s "<service>" -w "<value>" -U` | `security find-generic-password -a "<account>" -s "<service>" -w` |
| AWS Secrets Mgr | `aws secretsmanager create-secret --name <name> --secret-string "<value>"` | `aws secretsmanager get-secret-value --secret-id <name> --query SecretString --output text` |

These are the **exact** commands the recipe sections below expand on. When in doubt, use this table.

## Universal pattern (every manager)

The shape is the same regardless of vendor:

1. **Store the secret in the manager.** The value lives there forever; one place, one rotation.
2. **Write a reference (or pull-at-run-time setup) to the project's env/config file.** The file on disk never contains the literal value.
3. **Run the app via the manager's `run`-style command** so the value is injected as an env var only inside the app's process.

Pick the recipe below that matches your manager.

---

## 1Password (`op`)

Reference syntax: `op://<vault>/<item>/<field>`.

**Store**:

```bash
op item create \
  --category="API Credential" \
  --vault="<vault>" \
  --title="<service-name>" \
  credential="<the-value>"
```

To add a field to an existing item: `op item edit "<item>" --add credential="<value>"`.

**Write the reference**:

```
STRIPE_SECRET_KEY=op://<vault>/<service-name>/credential
```

**Run**:

```bash
op run --env-file=.env -- <command>
```

**Read one-off** (without echoing to chat):

```bash
op read op://<vault>/<service-name>/credential | <consumer>
```

---

## Bitwarden Secrets Manager (`bws`)

Reference syntax: secrets are referenced by UUID. Bitwarden Password Manager (`bw`) is a separate product — these instructions are for the **Secrets Manager** CLI (`bws`), which is the dev-secrets variant.

**Store** (creates a secret in a project):

```bash
bws secret create <key> "<value>" <project-id>
```

**Write the reference** (env file uses placeholders that `bws run` resolves):

```
STRIPE_SECRET_KEY={{ <secret-id> }}
```

**Run**:

```bash
bws run --env-file=.env -- <command>
```

If the team uses the older `bw` Password Manager CLI instead, the pattern is `bw get password <id>` for reads and shell substitution for env injection — no native `run` wrapper.

---

## Doppler

Doppler is project-centric — values live in a Doppler project, not in a per-file reference syntax. The env file on disk is essentially empty for managed values.

**Store**:

```bash
doppler secrets set STRIPE_SECRET_KEY="<value>" \
  --project=<project> --config=<env>
```

**Reference** in `.env`: typically you leave the key out of `.env` entirely. Doppler injects it from the cloud project at run time. For local dev defaults, use a separate `.env.example`.

**Run**:

```bash
doppler run -- <command>
```

Or pull values into a file once: `doppler secrets download --no-file --format=env > .env.doppler`. Don't commit that file.

---

## Infisical

Same model as Doppler — project-centric, runtime injection. Reference syntax in env files: `infisical://<workspace>/<env>/<key>` for places that need explicit paths, but typical usage just runs through the project.

**Store**:

```bash
infisical secrets set STRIPE_SECRET_KEY="<value>"
```

**Run**:

```bash
infisical run -- <command>
```

---

## HashiCorp Vault

Reference syntax: Vault Agent templates or env-injection via the SDK / `vault agent`. Manual `vault kv get` for one-offs.

**Store** (KV v2):

```bash
vault kv put secret/<path> stripe_key="<value>"
```

**Read** one-off:

```bash
vault kv get -field=stripe_key secret/<path>
```

**Run** via Vault Agent — this is configuration-heavy (`vault-agent.hcl` template that resolves the secret into a file or env var on startup). Use Vault Agent only when the user explicitly says "we use Vault" and is comfortable with the agent setup. For a quick dev workflow, prefer one of the simpler managers above.

---

## `pass` (Unix password store)

Plaintext after retrieval; no `run` wrapper. Best for individual developers, not teams.

**Store**:

```bash
echo "<value>" | pass insert -m <name>
```

**Read** (resolves to stdout):

```bash
pass show <name>
```

**Inject** into env at runtime via shell substitution in a wrapper script:

```bash
STRIPE_SECRET_KEY="$(pass show stripe/secret)" myapp
```

Don't put the substitution literal in a committed `.env` — write it in a `.envrc` (direnv) or a launcher script that the user runs locally.

---

## macOS Keychain (`security`)

Local-machine only. Good for personal dev setups, not for shared projects.

**Store**:

```bash
security add-generic-password -a "<account>" -s "<service>" -w "<value>" -U
```

**Read**:

```bash
security find-generic-password -a "<account>" -s "<service>" -w
```

Inject via shell substitution, same as `pass`.

---

## AWS Secrets Manager

For AWS-native apps, the canonical path is to read at process start via the AWS SDK (no plaintext anywhere on disk). For a quick local override, fetch and export:

```bash
export STRIPE_SECRET_KEY="$(aws secretsmanager get-secret-value \
  --secret-id stripe/secret \
  --query SecretString --output text)"
```

Don't commit the export to a script — use a launcher or your shell's local-only init file. Prefer SDK-side resolution in the app itself.

---

## Read side: using a credential to call something

Same priority order regardless of manager:

1. **If the project uses a `run`-style wrapper** (`op run`, `bws run`, `doppler run`, `infisical run`): the value is already in the app's environment. Tell the user to invoke their app/test/script via that wrapper. Don't resolve it yourself.

2. **If you need the value for a one-off shell command** (e.g., a curl test): resolve inline without echoing the value:

   ```bash
   AUTH="Bearer $(op read op://<vault>/<title>/credential)" \
     curl -H "Authorization: $AUTH" https://api.example.com/...
   ```

   Substitute the right `<read-command>` for the manager. The `after_tool_call` hook will catch leaks anyway, but design for "no plaintext ever in stdout/stderr" up front.

3. **Never paste the resolved value into chat** as confirmation. If the user wants to verify, they can read it themselves.

## When openclaw-shield blocks you

The `before_tool_call` hook (from openclaw-shield) blocks when the content you're writing matched a credential pattern. The block is correct — you tried to write a literal secret. Recover:

1. Acknowledge the block.
2. Ask which secret manager + which item/path the value should live in (if you don't already know).
3. Run the manager's `store` command (see the recipes above).
4. Retry the original write, but with a reference (or no value at all, if the manager pulls at run time).

## Anti-patterns — don't do these

- Writing `KEY=ghp_abc…` to `.env` because the user "just wants to test something". Use the right reference syntax and run via the manager.
- Asking the user to paste their API key into chat. Have them store it in their manager and give you the reference path.
- Calling `op read` / `vault kv get` / `pass show` and then `print`ing the value or `echo $TOKEN`-ing. The output-scan hook will warn, but better to design so plaintext never reaches stdout.
- Mixing managers ("I'll put this one in 1Password and this one in Doppler"). Pick the manager the project already uses; don't split.

## Why this matters

Literal credentials in files live forever — in git history, in backups, in editor undo buffers, in OS spotlight indexes, in CI build artifacts. References and runtime-injection are inert: re-keying a leaked credential is one CLI command, no file rewrites, no `BFG repo-cleaner` archaeology. Every modern secret manager exists because that's the correct model — pick one and use it consistently.
