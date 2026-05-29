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

  // Additional patterns sourced from NVIDIA garak's prompt-injection corpus
  // (garak/data/inthewild_jailbreak_llms.json — Apache 2.0) and the
  // PromptInject framework's templates (MIT, originally from
  // agencyenterprise/PromptInject). Each closes a specific shape our core
  // patterns above missed.

  // DAN-family persona names.
  /\b(STAN|DUDE|AIM|BetterDAN|EvilBOT|UCAR|UnGPT|Maximum|JailMommy)\b/,

  // Unfiltered / uncensored model claim.
  /\b(unfiltered|uncensored|unrestricted)\s+(response|version|mode|model|ai|chatbot|assistant)\b/i,

  // "never refuse / decline / deny" — DAN-system constraint.
  /\bnever\s+(refuse|decline|deny|warn|apologize|moralize)\b/i,

  // "will not refuse / decline / warn" — declarative variant.
  /\bwill\s+not\s+(refuse|decline|warn|apologize|moralize)\b/i,

  // "pretend you can do anything" — extends bare "pretend you are" with action claim.
  /\bpretend\b.{0,30}?\bcan\s+(do|access|generate|create)\s+(anything|everything|whatever)\b/i,

  // "bypass / remove / without all restrictions" — broader than safety-filter rule.
  /\b(without|bypass|ignore|remove)\s+(any|all|every|the)\s+(restriction|limitation|filter|guideline|guard|safety)/i,

  // "never break character" — DAN persistence instruction.
  /\bnever\s+break\s+character\b/i,

  // DAN token-system trick.
  /\byou\s+(have|start\s+with)\s+\d+\s+tokens\b/i,
  /\blose\s+\d+\s+tokens?\b/i,

  // "two responses, one as X and one as Y" — DAN-format dual-output ask.
  /\btwo\s+(different\s+)?responses?\b.{0,60}?\b(one|first|second)\b/i,

  // Labeled response prefixes: [CLASSIC]: ... [JAILBROKEN]: ... format.
  /(^|\n)\s*\[?\s*(CLASSIC|JAILBROKEN|NORMAL|LIBERATED|DEV|UNCENSORED)\s*\]?\s*:/i,

  // "STOP EVERYTHING NOW" — PromptInject's screaming-stop template.
  /\bstop\s+everything!*\s+(now|just|please)/i,

  // "ignore any/all previous and following instructions".
  /\bignore\s+(any|all)\s+(previous|prior|preceding)\s+(and\s+following\s+)?(instructions|prompts|rules)/i,

  // "spell-check the previous instructions" — prompt-leak via alternate verb.
  /\bspell[-\s]?check\s+(the\s+|your\s+)?(previous|prior|above)\s+(instructions|prompts)/i,

  // "print the previous instructions".
  /\bprint\s+(the|your)\s+(previous|prior|above)\s+(instructions|prompts|messages|system)/i,

  // "opposite of ChatGPT / Claude" — persona-inversion framing.
  /\bopposite\s+of\s+(chatgpt|claude|gpt|the\s+ai|the\s+assistant|the\s+chatbot)\b/i,
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
