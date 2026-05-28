// Ported from openclaw-shield/core/guardrails/secret-scan.py (SECRET_PATTERNS).
// Source of truth lives in this file for the OpenClaw adapter.

export type SecretPattern = {
  label: string;
  regex: RegExp;
};

export const SECRET_PATTERNS: SecretPattern[] = [
  // AWS
  { label: "AWS Access Key", regex: /AKIA[0-9A-Z]{16}/ },
  { label: "AWS Secret Key", regex: /aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}/ },

  // AI providers
  { label: "OpenAI API Key", regex: /sk-[A-Za-z0-9]{20,}/ },
  { label: "Anthropic API Key", regex: /sk-ant-[A-Za-z0-9_\-]{20,}/ },

  // GitHub
  { label: "GitHub PAT", regex: /ghp_[A-Za-z0-9]{36}/ },
  { label: "GitHub OAuth", regex: /gho_[A-Za-z0-9]{36}/ },
  { label: "GitHub App Token", regex: /ghs_[A-Za-z0-9]{36}/ },
  { label: "GitHub Fine-grained PAT", regex: /github_pat_[A-Za-z0-9_]{20,}/ },

  // GitLab
  { label: "GitLab PAT", regex: /glpat-[A-Za-z0-9_\-]{20,}/ },
  { label: "GitLab Deploy Token", regex: /gldt-[A-Za-z0-9_\-]{20,}/ },
  { label: "GitLab OAuth", regex: /glrt-[A-Za-z0-9_\-]{20,}/ },

  // Atlassian
  { label: "Atlassian API Token", regex: /ATATT3[A-Za-z0-9_\-]{20,}/ },

  // Stripe
  { label: "Stripe Secret Key", regex: /sk_live_[A-Za-z0-9]{24,}/ },
  { label: "Stripe Publishable Key", regex: /pk_live_[A-Za-z0-9]{24,}/ },

  // Slack
  { label: "Slack Bot Token", regex: /xoxb-[0-9]{10,}-[A-Za-z0-9]{20,}/ },
  { label: "Slack Webhook", regex: /hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{24}/ },

  // Google
  { label: "Google API Key", regex: /AIza[A-Za-z0-9_\-]{35}/ },

  // NPM
  { label: "NPM Token", regex: /npm_[A-Za-z0-9]{36}/ },

  // Private key headers
  { label: "Private Key Header", regex: /-----BEGIN\s+(RSA|EC|DSA|OPENSSH)?\s*PRIVATE\s+KEY-----/ },

  // Generic credential assignments (key=value or key: value with quoted value)
  { label: "Generic API Key Assignment", regex: /api[_-]?key\s*[:=]\s*['"][A-Za-z0-9_\-]{20,}['"]/i },
  { label: "Generic Secret Assignment",  regex: /secret\s*[:=]\s*['"][A-Za-z0-9_\-]{20,}['"]/i },
  { label: "Generic Token Assignment",   regex: /token\s*[:=]\s*['"][A-Za-z0-9_\-]{20,}['"]/i },
  { label: "Generic Password Assignment", regex: /password\s*[:=]\s*['"][^'"]{8,}['"]/i },

  // .env-style sensitive variables
  {
    label: "Env Variable Leak",
    regex: /(DATABASE_URL|DB_PASSWORD|REDIS_URL|MONGO_URI|JWT_SECRET|SESSION_SECRET|ENCRYPTION_KEY)\s*=\s*\S{8,}/,
  },
];

export type SecretMatch = {
  label: string;
  index: number;
  match: string;
};

export function scanSecrets(text: string): SecretMatch[] {
  if (!text) return [];
  const findings: SecretMatch[] = [];
  for (const { label, regex } of SECRET_PATTERNS) {
    // Force a non-global regex so .exec/.test don't carry lastIndex state across calls.
    const m = text.match(regex);
    if (m && m.index !== undefined) {
      findings.push({ label, index: m.index, match: m[0] });
    }
  }
  return findings;
}

export function redactSecrets(text: string): { text: string; findings: SecretMatch[] } {
  const findings = scanSecrets(text);
  if (findings.length === 0) return { text, findings };
  let out = text;
  for (const f of findings) {
    // Mask: keep first 4 + last 4 chars so the token is identifiable but not leaked.
    const masked =
      f.match.length > 12
        ? `${f.match.slice(0, 4)}…${f.match.slice(-4)}`
        : "[REDACTED]";
    out = out.split(f.match).join(`[openclaw-shield redacted: ${f.label} → ${masked}]`);
  }
  return { text: out, findings };
}
