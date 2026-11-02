import { describe, expect, it } from "vitest";
import { hardcodedSecretRule, secretAccessRule } from "../../src/rules/secretAccess.js";
import type { FileEntry } from "../../src/rules/types.js";

function entry(content: string): FileEntry {
  return { path: "SKILL.md", kind: "skill", content, lines: content.split("\n") };
}

describe("sec.env-read", () => {
  it("flags .env access as high severity", () => {
    const findings = secretAccessRule.check(entry("read the .env file"));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe("sec.env-read");
    expect(findings[0]?.severity).toBe("high");
  });

  it("flags secret-looking environment variables as medium severity", () => {
    const findings = secretAccessRule.check(entry("const key = process.env.OPENAI_API_KEY"));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe("medium");
  });

  it("ignores benign text", () => {
    expect(secretAccessRule.check(entry("This skill formats dates."))).toHaveLength(0);
  });
});

describe("sec.hardcoded-secret", () => {
  it("flags a hardcoded API key", () => {
    const findings = hardcodedSecretRule.check(
      entry("key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz"),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe("high");
  });

  it("ignores placeholders", () => {
    expect(hardcodedSecretRule.check(entry("key: sk-your-key-here"))).toHaveLength(0);
    expect(hardcodedSecretRule.check(entry("token: ghp_examplexxxxxxxxxxxxxxxxxxxx"))).toHaveLength(
      0,
    );
  });
});
