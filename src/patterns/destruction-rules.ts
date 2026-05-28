// Ported from openclaw-shield/core/guardrails/destruction-scan.py (PATTERNS).
// The Python source uses re.VERBOSE; we inline the same patterns here without
// whitespace/comments so they match the same shell strings.

export type DestructionRule = {
  label: string;
  regex: RegExp;
  reason: string;
};

// Catastrophic destination paths: /, /etc, /usr, /var, $HOME, ~, --no-preserve-root targets.
// Keep this in sync with `_DANGEROUS_PATH` in destruction-scan.py.
const DANGEROUS_PATH =
  "(?:--no-preserve-root\\s+)?(?:/|/etc|/etc/[^\\s|;&]*|/usr|/usr/[^\\s|;&]*|/var|/var/[^\\s|;&]*|/bin|/bin/[^\\s|;&]*|/sbin|/sbin/[^\\s|;&]*|/lib|/lib/[^\\s|;&]*|/boot|/boot/[^\\s|;&]*|/sys|/sys/[^\\s|;&]*|/proc|/proc/[^\\s|;&]*|/dev|/dev/[^\\s|;&]*|/Users(?:/[^\\s|;&]*)?|/home(?:/[^\\s|;&]*)?|\\$HOME(?:/[^\\s|;&]*)?|~(?:/[^\\s|;&]*)?)";

export const DESTRUCTION_RULES: DestructionRule[] = [
  {
    label: "rm -rf root / system-dir / home",
    regex: new RegExp(
      `\\brm\\s+(?:(?:-[a-zA-Z]*[rR][a-zA-Z]*|--recursive)(?:\\s+-[a-zA-Z]+|\\s+--[a-zA-Z]+)*)\\s+(?:--\\s+)?${DANGEROUS_PATH}(?=\\s|$)`,
    ),
    reason: "Recursive delete targeting filesystem root, a system directory, or the user's home.",
  },
  {
    label: "find / -delete",
    regex: new RegExp(`\\bfind\\s+${DANGEROUS_PATH}(?=\\s)[^|;&\\n]*\\s-delete\\b`),
    reason: "Recursive deletion rooted at filesystem root, a system directory, or home.",
  },
  {
    label: "chmod -R 777 catastrophic-path",
    regex: new RegExp(
      `\\bchmod\\s+(?:-[a-zA-Z]*R[a-zA-Z]*|--recursive)(?:\\s+-[a-zA-Z]+|\\s+--[a-zA-Z]+)*\\s+(?:0?777)\\s+${DANGEROUS_PATH}(?=\\s|$)`,
    ),
    reason: "Recursively world-writable from filesystem root, a system directory, or home.",
  },
  {
    label: "dd to block device",
    regex: /\bdd\b[^|;&\n]*\bof=\/dev\/(?:sd[a-z]|disk\d|nvme\d|hd[a-z]|mmcblk\d)/,
    reason: "Writes raw bytes to a block device — destroys the disk.",
  },
  {
    label: "mkfs on block device",
    regex: /\bmkfs(?:\.[a-z0-9]+)?\s+(?:-[^\s]+\s+)*\/dev\/(?:sd[a-z]|disk\d|nvme\d|hd[a-z])/,
    reason: "Reformats a block device.",
  },
  {
    label: "git force-push to main/master",
    regex: /\bgit\s+push\s+(?:--force\b|--force-with-lease\b|-f\b)[^|;&\n]*\b(?:main|master|trunk|production|prod)\b/,
    reason: "Force-push to a protected branch rewrites shared history.",
  },
  {
    label: "git push --force to main (verb-then-flag)",
    regex: /\bgit\s+push\s+(?:[^\s|;&]+\s+)+\b(?:main|master|trunk|production|prod)\b[^|;&\n]*(?:--force\b|--force-with-lease\b|\s-f\b)/,
    reason: "Force-push to a protected branch rewrites shared history.",
  },
  {
    label: "terraform destroy (no --target)",
    regex: /\b(?:terraform|tofu)\s+destroy\b(?![^|;&\n]*--target)/,
    reason: "Tears down every resource in the state file. Use --target for surgical destroys.",
  },
  {
    label: "kubectl delete namespace",
    regex: /\bkubectl\s+(?:[^\s|;&]+\s+)*delete\s+(?:ns|namespaces?)\b/,
    reason: "Deletes an entire namespace — every workload, every PVC, every secret.",
  },
  {
    label: "kubectl delete --all without selector",
    regex: /\bkubectl\s+(?:[^\s|;&]+\s+)*delete\s+[^\s|;&]+\s+--all\b(?![^|;&\n]*(?:--selector|-l\s))/,
    reason: "Deletes every resource of the type — no label scope.",
  },
  {
    label: "DROP DATABASE",
    regex: /\bDROP\s+DATABASE\b/i,
    reason: "Drops an entire database.",
  },
];

export type DestructionMatch = {
  label: string;
  reason: string;
  match: string;
};

export function scanDestruction(command: string): DestructionMatch | null {
  if (!command) return null;
  // Split by shell separators so each segment is judged independently.
  const segments = command.split(/[;&\n]|\|\|?/);
  for (const seg of segments) {
    const trimmed = seg.trim();
    if (!trimmed) continue;
    for (const rule of DESTRUCTION_RULES) {
      const m = trimmed.match(rule.regex);
      if (m) {
        return { label: rule.label, reason: rule.reason, match: m[0] };
      }
    }
  }
  return null;
}
