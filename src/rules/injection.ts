import { toSafeSnippet } from "../util/text.js";
import type { FileEntry, Finding, Rule } from "./types.js";

export const IMPERATIVE_PATTERNS: RegExp[] = [
  /\bignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|earlier|above)\s+instructions?\b/i,
  /\bdisregard\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|earlier|above)\s+(?:instructions?|guidance|rules)\b/i,
  /\bdo\s+not\s+(?:tell|inform|notify|reveal\s+to)\s+the\s+user\b/i,
  /\bwithout\s+(?:asking|informing|telling|user\s+confirmation|confirmation)\b/i,
];

function lineOf(lines: string[], needle: string): number | undefined {
  const index = lines.findIndex((line) => line.includes(needle));
  return index >= 0 ? index + 1 : undefined;
}

const ignorePreviousRule: Rule = {
  id: "inj.ignore-previous",
  severity: "high",
  confidence: "medium",
  description: "Detects instruction-hijack phrasing commonly used in prompt injection.",
  check(entry: FileEntry): Finding[] {
    const findings: Finding[] = [];
    entry.lines.forEach((line, index) => {
      for (const pattern of IMPERATIVE_PATTERNS) {
        if (pattern.test(line)) {
          findings.push({
            ruleId: "inj.ignore-previous",
            severity: "high",
            confidence: "medium",
            message: "Instruction-hijack phrasing (prompt injection).",
            file: entry.path,
            line: index + 1,
            snippet: toSafeSnippet(line),
            remediation: "Remove or rewrite instructions that override the user.",
          });
        }
      }
    });
    return findings;
  },
};

const COMMENT_RE = /<!--([\s\S]*?)-->/g;
const HIDDEN_KEYWORDS_RE = /\b(ignore|instruction|exfiltrat|secret|password|token|override)\b/i;

const hiddenInstructionRule: Rule = {
  id: "inj.hidden-instruction",
  severity: "high",
  confidence: "low",
  description: "Instruction-like content hidden in HTML comments.",
  check(entry: FileEntry): Finding[] {
    const findings: Finding[] = [];
    const matches = entry.content.matchAll(COMMENT_RE);
    for (const match of matches) {
      const inner = match[1] ?? "";
      if (
        IMPERATIVE_PATTERNS.some((pattern) => pattern.test(inner)) ||
        HIDDEN_KEYWORDS_RE.test(inner)
      ) {
        findings.push({
          ruleId: "inj.hidden-instruction",
          severity: "high",
          confidence: "low",
          message: "Instruction-like text is hidden in an HTML comment.",
          file: entry.path,
          line: lineOf(entry.lines, "<!--"),
          snippet: toSafeSnippet(inner),
          remediation: "Review why instructions are hidden from the rendered text.",
        });
      }
    }
    return findings;
  },
};

const SYSTEM_PROMPT_RE =
  /\b(reveal|show|print|repeat|leak|ignore|override|replace|disclose)\b[^\n]{0,40}\b(system prompt|your (?:initial )?(?:instructions|prompt|rules)|hidden (?:instructions|prompt)|developer message)\b/i;

const systemPromptRule: Rule = {
  id: "inj.system-prompt",
  severity: "medium",
  confidence: "low",
  description: "Attempts to reveal, replace, or ignore the system prompt.",
  check(entry: FileEntry): Finding[] {
    const findings: Finding[] = [];
    entry.lines.forEach((line, index) => {
      if (SYSTEM_PROMPT_RE.test(line)) {
        findings.push({
          ruleId: "inj.system-prompt",
          severity: "medium",
          confidence: "low",
          message: "References revealing or overriding the system prompt.",
          file: entry.path,
          line: index + 1,
          snippet: toSafeSnippet(line),
          remediation: "Remove attempts to inspect or replace the system prompt.",
        });
      }
    });
    return findings;
  },
};

const SELF_PERSIST_PATTERNS: RegExp[] = [
  /\b(?:add|append|write|save|store|record)\b[^\n]{0,40}\b(?:to|into|in)\b[^\n]{0,20}\b(?:your|the|agent'?s?)\s+(?:long[- ]term\s+|persistent\s+)?memory\b/i,
  /\bremember\b[^\n]{0,50}\b(?:for|in|across)\b[^\n]{0,20}\b(?:all|future|every|subsequent)\b[^\n]{0,20}\b(?:conversations?|sessions?|requests?|interactions?|chats?)\b/i,
  /\b(?:update|modify|edit|append\s+to|write\s+to|add\s+to)\b[^\n]{0,30}\b(?:your|the)\s+(?:CLAUDE\.md|AGENTS\.md|GEMINI\.md|\.cursorrules|memory\s+file|system\s+prompt)\b/i,
  /\bfor\s+all\s+(?:future|subsequent|following)\b[^\n]{0,20}\b(?:requests?|conversations?|sessions?|responses?|interactions?)\b/i,
  /\b(?:in|across)\s+all\s+(?:future|subsequent)\b[^\n]{0,20}\b(?:responses?|conversations?|sessions?|requests?)\b/i,
];

const selfPersistRule: Rule = {
  id: "inj.self-persist",
  severity: "high",
  confidence: "medium",
  description: "Instructions that persist themselves into memory or other context files.",
  check(entry: FileEntry): Finding[] {
    const findings: Finding[] = [];
    entry.lines.forEach((line, index) => {
      if (SELF_PERSIST_PATTERNS.some((pattern) => pattern.test(line))) {
        findings.push({
          ruleId: "inj.self-persist",
          severity: "high",
          confidence: "medium",
          message: "Instruction tries to persist itself across sessions or into other files.",
          file: entry.path,
          line: index + 1,
          snippet: toSafeSnippet(line),
          remediation:
            "Remove self-propagating instructions; a skill must not rewrite memory or context.",
        });
      }
    });
    return findings;
  },
};

const JAILBREAK_PATTERNS: RegExp[] = [
  /\bdo\s+anything\s+now\b/i,
  /\bDAN\b[^\n]{0,40}\b(?:jailbreak|mode|do anything)\b/i,
  /\b(?:developer|unrestricted|god|jailbreak|uncensored|unfiltered)\s+mode\b/i,
  /\byou\s+are\s+now\b[^\n]{0,50}\b(?:unrestricted|uncensored|unfiltered|free|dan|jailbroken|evil|amoral|without)\b/i,
  /\b(?:bypass|disable|ignore|remove|turn\s+off|override)\b[^\n]{0,30}\b(?:content\s+filters?|safety\s+(?:rules|guidelines|filters|restrictions|measures)|guardrails|ethical\s+guidelines)\b/i,
  /\b(?:no\s+rules\s+or\s+restrictions|without\s+any\s+(?:rules|restrictions|limits|guidelines|filters))\b/i,
  /\b(?:pretend|act|behave)\b[^\n]{0,20}\b(?:to\s+be|as|like)\b[^\n]{0,40}\b(?:an?\s+(?:unrestricted|uncensored|unfiltered|evil|amoral)|AI\s+without\s+(?:safety|rules|restrictions))\b/i,
  /\bfrom\s+now\s+on\b[^\n]{0,40}\b(?:ignore|bypass|disable)\b[^\n]{0,25}\b(?:all|any|your)\b[^\n]{0,20}\b(?:safety|rules|restrictions|guidelines)\b/i,
];

const jailbreakPersonaRule: Rule = {
  id: "inj.jailbreak-persona",
  severity: "high",
  confidence: "medium",
  description: "Jailbreak or persona-reassignment phrasing that removes safety constraints.",
  check(entry: FileEntry): Finding[] {
    const findings: Finding[] = [];
    entry.lines.forEach((line, index) => {
      if (JAILBREAK_PATTERNS.some((pattern) => pattern.test(line))) {
        findings.push({
          ruleId: "inj.jailbreak-persona",
          severity: "high",
          confidence: "medium",
          message: "Jailbreak/persona phrasing attempts to remove safety constraints.",
          file: entry.path,
          line: index + 1,
          snippet: toSafeSnippet(line),
          remediation: "Remove jailbreak or role-override instructions from the skill.",
        });
      }
    });
    return findings;
  },
};

export const injectionRules: Rule[] = [
  ignorePreviousRule,
  hiddenInstructionRule,
  systemPromptRule,
  selfPersistRule,
  jailbreakPersonaRule,
];
