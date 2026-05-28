# Security policy

## Reporting a vulnerability

If you find a way to bypass any of openclaw-shield's guardrails — sneaking a credential through `before_tool_call`, a destructive command through `destruction-scan`, prompt injection past `inbound_claim`, secrets through `before_dispatch` or `before_prompt_build` — please report it privately first.

**Email**: open a private security advisory on this repo's GitHub Security tab (Security → Advisories → New draft security advisory), or reach the maintainer via the email on their GitHub profile.

Please **do not** open a public GitHub issue or post a proof-of-concept payload to a public channel until a fix has shipped.

## What we consider in scope

- A regex bypass that lets a known credential format slip past `secret-patterns.ts`.
- A shell-injection payload that the agent can pass through `before_tool_call` to execute a destructive operation the destruction rules should have caught.
- A prompt-injection construction that escapes detection in `inbound_claim` AND succeeds in extracting the system prompt / instructions from the agent.
- A path that loads or executes attacker-controlled code through the plugin (no execution surface is intentional today — but if you find one, report it).
- A way to exfiltrate the secret cache (`$TMPDIR/.openclaw-shield-cache.<uid>/`) more cheaply than the documented threat model already permits.

## What we consider out of scope

- The 1Password secret cache uses a per-platform passphrase backend:
  - On **macOS**, the passphrase lives in the user's Keychain (service `openclaw-shield`). A cache-dir reader can't decrypt anything without also unlocking the Keychain. Reports here need to bypass *both* layers (or the standard macOS Keychain consent model) to be in scope.
  - On other platforms (or with `OPENCLAW_SHIELD_PASSPHRASE_BACKEND=file`), the passphrase falls back to a `.salt` file in the cache dir. This is **obfuscation against backup scanners, not encryption** against an attacker with read access to the user's home directory. Reports about "the .salt file is readable" on this fallback path will be closed — it's documented behavior.
- False positives in pattern matching (e.g. the secret regex flagging a non-secret string). File those as normal issues, not security advisories.
- Resource-exhaustion attacks via giant message bodies (the host should rate-limit / size-cap before openclaw-shield sees the message; if it doesn't, that's an openclaw issue).
- Anything that requires write access to the openclaw config (`plugins.entries.openclaw-shield`) — the threat model assumes the operator controls that file.

## What happens after a report

1. Acknowledgment within ~72 hours.
2. Investigation. If reproducible, a CVE-eligible fix lands on `main` and is tagged.
3. Public disclosure of the issue after the fix is shipped, with credit to the reporter unless they prefer anonymity.

This is a maintained-as-time-permits project, not a 24/7 product. Expect best-effort response times.
