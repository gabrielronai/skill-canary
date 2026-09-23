export { scan } from "./scan.js";
export type { ScanOptions } from "./scan.js";
export { ALL_RULES, ALL_RULE_IDS, selectRules } from "./rules/registry.js";
export { meetsThreshold, SEVERITY_ORDER } from "./rules/types.js";
export type {
  Confidence,
  FailThreshold,
  FileEntry,
  FileKind,
  Finding,
  Rule,
  Severity,
} from "./rules/types.js";
