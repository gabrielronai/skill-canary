import { describe, expect, it } from "vitest";
import { obfuscationRules } from "../../src/rules/obfuscation.js";
import type { FileEntry } from "../../src/rules/types.js";

const zeroWidthRule = obfuscationRules.find((rule) => rule.id === "obf.zero-width");
if (!zeroWidthRule) {
  throw new Error("obf.zero-width rule is missing");
}

function entry(content: string): FileEntry {
  return { path: "SKILL.md", kind: "skill", content, lines: content.split("\n") };
}

describe("obf.zero-width", () => {
  it("flags hidden zero-width characters and shows them escaped", () => {
    const findings = zeroWidthRule.check(entry("hello\u200Bworld"));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe("obf.zero-width");
    expect(findings[0]?.snippet).toContain("\\u200B");
  });

  it("ignores plain text", () => {
    expect(zeroWidthRule.check(entry("hello world"))).toHaveLength(0);
  });
});
