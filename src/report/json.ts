import type { Finding, Severity } from "../rules/types.js";
import { TOOL_NAME, TOOL_VERSION } from "../version.js";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export interface JsonReport {
  tool: string;
  version: string;
  summary: {
    total: number;
    bySeverity: Record<Severity, number>;
  };
  findings: Finding[];
}

export function buildJsonReport(findings: Finding[]): JsonReport {
  const bySeverity = Object.fromEntries(SEVERITIES.map((severity) => [severity, 0])) as Record<
    Severity,
    number
  >;
  for (const finding of findings) {
    bySeverity[finding.severity] += 1;
  }
  return {
    tool: TOOL_NAME,
    version: TOOL_VERSION,
    summary: { total: findings.length, bySeverity },
    findings,
  };
}

export function formatJson(findings: Finding[]): string {
  return `${JSON.stringify(buildJsonReport(findings), null, 2)}\n`;
}
