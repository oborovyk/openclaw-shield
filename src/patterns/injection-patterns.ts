// Ported from openclaw-shield/core/guardrails/prompt-injection-scan.py (PATTERNS).

export const INJECTION_PATTERNS: RegExp[] = [
  // Instruction override
  /ignore\s+(all\s+)?(previous|prior|above|earlier|preceding)\s+(instructions|prompts|rules|directives|context)/i,
  /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)/i,
  /forget\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules|context)/i,
  /override\s+(all\s+)?(system|previous|safety)\s+(instructions|prompts|rules|checks|filters|guards)/i,
  /override\s+(system|safety|security)\s+/i,

  // Role manipulation
  /you\s+are\s+now\s+(a|an|my)\s+/i,
  /from\s+now\s+on\s+(you|pretend|act|behave)/i,
  /pretend\s+(you\s+are|to\s+be)\s+/i,
  /act\s+as\s+(a|an|if|my)\s+/i,
  /roleplay\s+as\s+/i,
  /assume\s+the\s+role\s+of\s+/i,

  // System prompt extraction
  /output\s+(your|the)\s+(system\s+)?(prompt|instructions)/i,
  /reveal\s+(your|the)\s+(system\s+)?(prompt|instructions)/i,
  /show\s+me\s+(your|the)\s+(system\s+)?(prompt|instructions)/i,
  /print\s+(your|the)\s+(system\s+)?(prompt|instructions)/i,
  /what\s+(is|are)\s+(your|the)\s+(system\s+)?(prompt|instructions)/i,
  /repeat\s+(your|the|all)\s+(system\s+)?(prompt|instructions|rules)/i,

  // Fake message boundaries
  /<\/?system>/i,
  /<\/?assistant>/i,
  /<\/?human>/i,
  /\[SYSTEM\]/i,
  /\[\/SYSTEM\]/i,
  /\[INST\]/i,
  /\[\/INST\]/i,
  /<<SYS>>/,
  /<<\/SYS>>/,

  // Code-exec smuggling
  /eval\s*\(\s*['"]/i,
  /exec\s*\(\s*['"]/i,
  /Function\s*\(\s*['"].*return/i,

  // Jailbreak / DAN
  /do\s+anything\s+now/i,
  /DAN\s+mode/i,
  /developer\s+mode\s+(enabled|output|activated)/i,
  /jailbreak/i,
  /bypass\s+(safety|content|security)\s+(filter|check|rule|guard)/i,
];

export type InjectionMatch = {
  pattern: string;
  index: number;
  match: string;
};

export function scanInjection(text: string): InjectionMatch[] {
  if (!text) return [];
  const findings: InjectionMatch[] = [];
  for (const regex of INJECTION_PATTERNS) {
    const m = text.match(regex);
    if (m && m.index !== undefined) {
      findings.push({ pattern: regex.source, index: m.index, match: m[0] });
    }
  }
  return findings;
}
