import { ALL_RULES } from "../rules/registry.js";
import type { Finding, Severity } from "../rules/types.js";
import { TOOL_NAME, TOOL_VERSION } from "../version.js";

const LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

/** SARIF 2.1.0 report for GitHub code scanning and other CI consumers. */
export function formatSarif(findings: Finding[]): string {
  const usedRuleIds = new Set(findings.map((finding) => finding.ruleId));
  const rules = ALL_RULES.filter((rule) => usedRuleIds.has(rule.id)).map((rule) => ({
    id: rule.id,
    name: rule.id,
    shortDescription: { text: rule.description },
    defaultConfiguration: { level: LEVEL[rule.severity] },
    properties: { tags: ["security"], precision: rule.confidence },
  }));

  const results = findings.map((finding) => ({
    ruleId: finding.ruleId,
    level: LEVEL[finding.severity],
    message: {
      text: finding.snippet ? `${finding.message} (${finding.snippet})` : finding.message,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: finding.file },
          ...(finding.line ? { region: { startLine: finding.line } } : {}),
        },
      },
    ],
    properties: {
      severity: finding.severity,
      confidence: finding.confidence,
      ...(finding.remediation ? { remediation: finding.remediation } : {}),
    },
  }));

  const sarif = {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: { driver: { name: TOOL_NAME, version: TOOL_VERSION, rules } },
        results,
      },
    ],
  };
  return `${JSON.stringify(sarif, null, 2)}\n`;
}
