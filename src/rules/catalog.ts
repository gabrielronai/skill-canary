import { ALL_RULES } from "./registry.js";
import type { Confidence, Severity } from "./types.js";

/** Stable, machine-readable view of a rule. */
export interface RuleInfo {
  id: string;
  severity: Severity;
  confidence: Confidence;
  description: string;
  kinds: string[];
}

/** The rule registry as data, for `rules --json`, docs, and integrations. */
export function ruleCatalog(): RuleInfo[] {
  return ALL_RULES.map((rule) => ({
    id: rule.id,
    severity: rule.severity,
    confidence: rule.confidence,
    description: rule.description,
    kinds: rule.kinds ? [...rule.kinds] : ["all"],
  }));
}
