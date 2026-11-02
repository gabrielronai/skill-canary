import { describe, expect, it } from "vitest";
import { obfuscationRules } from "../../src/rules/obfuscation.js";
import type { FileEntry } from "../../src/rules/types.js";

const zeroWidthRule = obfuscationRules.find((rule) => rule.id === "obf.zero-width");
if (!zeroWidthRule) {
  throw new Error("obf.zero-width rule is missing");
}

const unicodeTagRule = obfuscationRules.find((rule) => rule.id === "obf.unicode-tag");
if (!unicodeTagRule) {
  throw new Error("obf.unicode-tag rule is missing");
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

describe("obf.unicode-tag", () => {
  it("flags invisible tag characters and escapes them", () => {
    const findings = unicodeTagRule.check(
      entry("hello\u{E0069}\u{E0067}\u{E006E}\u{E006F}\u{E0072}"),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.snippet).toContain("\\u{E0069}");
  });

  it("ignores plain text with emoji variation selectors", () => {
    expect(unicodeTagRule.check(entry("hello \u2764\uFE0F world"))).toHaveLength(0);
  });
});
