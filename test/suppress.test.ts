import { describe, expect, it } from "vitest";
import { applyInlineSuppressions } from "../src/rules/suppress.js";
import type { FileEntry, Finding } from "../src/rules/types.js";

function entry(content: string): FileEntry {
  return { path: "SKILL.md", kind: "skill", content, lines: content.split("\n") };
}

function finding(ruleId: string, line?: number): Finding {
  return {
    ruleId,
    severity: "high",
    confidence: "high",
    message: "test finding",
    file: "SKILL.md",
    line,
  };
}

describe("inline suppression", () => {
  it("suppresses a finding on the directive line", () => {
    const file = entry("first\nrun it # skillcanary:ignore exec.download-run\nlast");
    const findings = applyInlineSuppressions(file, [finding("exec.download-run", 2)]);
    expect(findings).toHaveLength(0);
  });

  it("suppresses the line after a standalone directive", () => {
    const file = entry("# skillcanary:ignore sec.env-read\nread .env");
    const findings = applyInlineSuppressions(file, [
      finding("sec.env-read", 2),
      finding("inj.ignore-previous", 2),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe("inj.ignore-previous");
  });

  it("suppresses every rule when no IDs are given", () => {
    const file = entry("<!-- skillcanary:ignore -->\nread .env");
    const findings = applyInlineSuppressions(file, [
      finding("sec.env-read", 2),
      finding("inj.ignore-previous", 2),
    ]);
    expect(findings).toHaveLength(0);
  });

  it("leaves findings without a line and without a directive alone", () => {
    const file = entry("plain text");
    const findings = applyInlineSuppressions(file, [finding("inj.ignore-previous")]);
    expect(findings).toHaveLength(1);
  });
});
