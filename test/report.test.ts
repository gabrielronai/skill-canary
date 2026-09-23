import { describe, expect, it } from "vitest";
import { formatJson } from "../src/report/json.js";
import { formatSarif } from "../src/report/sarif.js";
import type { Finding } from "../src/rules/types.js";

const findings: Finding[] = [
  {
    ruleId: "inj.ignore-previous",
    severity: "high",
    confidence: "medium",
    message: "Instruction-hijack phrasing.",
    file: "a/SKILL.md",
    line: 3,
  },
  {
    ruleId: "hygiene.http",
    severity: "low",
    confidence: "low",
    message: "Plaintext HTTP URL.",
    file: "b/mcp.json",
  },
];

describe("json reporter", () => {
  it("emits tool, summary, and findings", () => {
    const report = JSON.parse(formatJson(findings));
    expect(report.tool).toBe("skillcanary");
    expect(report.summary.total).toBe(2);
    expect(report.summary.bySeverity.high).toBe(1);
    expect(report.summary.bySeverity.low).toBe(1);
    expect(report.summary.bySeverity.critical).toBe(0);
    expect(report.findings).toHaveLength(2);
  });
});

describe("sarif reporter", () => {
  it("emits SARIF 2.1.0 with mapped levels and used rules", () => {
    const sarif = JSON.parse(formatSarif(findings));
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].tool.driver.name).toBe("skillcanary");
    expect(sarif.runs[0].results).toHaveLength(2);
    expect(sarif.runs[0].results[0].level).toBe("error");
    expect(sarif.runs[0].results[0].ruleId).toBe("inj.ignore-previous");
    expect(sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine).toBe(3);
    expect(sarif.runs[0].results[1].level).toBe("note");
    const ruleIds = sarif.runs[0].tool.driver.rules.map((rule: { id: string }) => rule.id);
    expect(ruleIds).toContain("inj.ignore-previous");
    expect(ruleIds).not.toContain("mcp.shadow");
  });
});
