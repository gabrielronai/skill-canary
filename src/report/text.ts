import { SEVERITY_ORDER } from "../rules/types.js";
import type { Finding, Severity } from "../rules/types.js";
import { bold, colorize, dim } from "../util/color.js";

export interface TextReportOptions {
  color: boolean;
}

const SEVERITY_DISPLAY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

function summarize(findings: Finding[]): string {
  const counts = new Map<Severity, number>();
  for (const finding of findings) {
    counts.set(finding.severity, (counts.get(finding.severity) ?? 0) + 1);
  }
  return SEVERITY_DISPLAY_ORDER.filter((severity) => counts.has(severity))
    .map((severity) => `${counts.get(severity)} ${severity}`)
    .join(", ");
}

/** Render findings as a grouped, ANSI-safe human-readable report. */
export function formatText(findings: Finding[], options: TextReportOptions): string {
  if (findings.length === 0) {
    return "No findings.\n";
  }

  const byFile = new Map<string, Finding[]>();
  for (const finding of findings) {
    const list = byFile.get(finding.file) ?? [];
    list.push(finding);
    byFile.set(finding.file, list);
  }

  const lines: string[] = [];
  for (const file of [...byFile.keys()].sort()) {
    lines.push(bold(file, options.color));
    for (const finding of byFile.get(file) ?? []) {
      const location = finding.line ? `:${finding.line}` : "";
      const label = finding.severity.toUpperCase().padEnd(8);
      lines.push(
        `  ${colorize(label, finding.severity, options.color)} ${finding.ruleId}${location}`,
      );
      lines.push(`    ${finding.message}`);
      if (finding.snippet) {
        lines.push(dim(`    > ${finding.snippet}`, options.color));
      }
      if (finding.remediation) {
        lines.push(dim(`    fix: ${finding.remediation}`, options.color));
      }
    }
  }

  lines.push("");
  lines.push(`${findings.length} finding(s): ${summarize(findings)}`);
  return `${lines.join("\n")}\n`;
}

/** Sort helper shared with JSON/SARIF reporters in M1. */
export function bySeverity(a: Finding, b: Finding): number {
  return SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
}
