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

export const injectionRules: Rule[] = [ignorePreviousRule, hiddenInstructionRule, systemPromptRule];
