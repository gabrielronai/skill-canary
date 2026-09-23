import { destructiveRule, downloadRunRule, dynamicExecRule } from "./execution.js";
import { exfiltrationRules } from "./exfiltration.js";
import { hookRule } from "./hooks.js";
import { hygieneRules } from "./hygiene.js";
import { injectionRules } from "./injection.js";
import { mcpRules } from "./mcp.js";
import { obfuscationRules } from "./obfuscation.js";
import { skillPermissionsRule } from "./permissions.js";
import { secretAccessRule } from "./secretAccess.js";
import type { FileEntry, Finding, Rule } from "./types.js";

/** Every rule the scanner knows about, in reporting order. */
export const ALL_RULES: Rule[] = [
  ...injectionRules,
  ...obfuscationRules,
  secretAccessRule,
  ...executionRules(),
  ...exfiltrationRules,
  hookRule,
  skillPermissionsRule,
  ...hygieneRules,
  ...mcpRules,
];

function executionRules(): Rule[] {
  return [destructiveRule, downloadRunRule, dynamicExecRule];
}

export const ALL_RULE_IDS: string[] = ALL_RULES.map((rule) => rule.id);

export function selectRules(ids?: string[]): Rule[] {
  if (!ids || ids.length === 0) {
    return ALL_RULES;
  }
  const wanted = new Set(ids);
  return ALL_RULES.filter((rule) => wanted.has(rule.id));
}

function appliesTo(rule: Rule, entry: FileEntry): boolean {
  return rule.kinds === undefined || rule.kinds.includes(entry.kind);
}

/** Run the given rules over every entry. A failing rule never aborts the scan. */
export function runRules(entries: FileEntry[], rules: Rule[]): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();

  for (const entry of entries) {
    for (const rule of rules) {
      if (!appliesTo(rule, entry)) {
        continue;
      }
      let produced: Finding[];
      try {
        produced = rule.check(entry);
      } catch {
        // A misbehaving rule is non-fatal; skip it for this entry.
        continue;
      }
      for (const finding of produced) {
        const key = `${finding.ruleId}|${finding.file}|${finding.line ?? ""}|${finding.message}`;
        if (!seen.has(key)) {
          seen.add(key);
          findings.push(finding);
        }
      }
    }
  }
  return findings;
}
