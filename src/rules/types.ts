/**
 * Core domain types shared by the scanner, rules, and reporters.
 */

import type { McpConfig } from "../mcp/model.js";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Confidence = "high" | "medium" | "low";

export type FileKind =
  | "skill"
  | "mcp"
  | "script"
  | "config"
  | "agentconfig"
  | "instructions"
  | "other";

/** Parsed frontmatter of a SKILL.md. */
export interface SkillMeta {
  name?: string;
  description?: string;
  allowedTools: string[];
}

/** A file that has been read and is eligible for rule evaluation. */
export interface FileEntry {
  /** Path relative to the scan root, using forward slashes. */
  path: string;
  kind: FileKind;
  content: string;
  lines: string[];
  /** Parsed MCP config, present when `kind` is `mcp`. */
  mcp?: McpConfig;
  /** Parsed skill frontmatter, present when `kind` is `skill`. */
  skill?: SkillMeta;
}

/** A single problem reported by a rule. */
export interface Finding {
  ruleId: string;
  severity: Severity;
  confidence: Confidence;
  message: string;
  file: string;
  line?: number;
  column?: number;
  snippet?: string;
  remediation?: string;
}

/** A heuristic check over a file entry. */
export interface Rule {
  id: string;
  severity: Severity;
  confidence: Confidence;
  description: string;
  /** Only run this rule for these file kinds (all kinds when omitted). */
  kinds?: FileKind[];
  check(entry: FileEntry): Finding[];
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export type FailThreshold = Severity | "none";

/** True when `severity` should fail the run for the given threshold. */
export function meetsThreshold(severity: Severity, threshold: FailThreshold): boolean {
  if (threshold === "none") {
    return false;
  }
  return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[threshold];
}
