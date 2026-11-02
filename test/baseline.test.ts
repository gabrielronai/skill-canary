import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { fingerprint, loadBaseline, writeBaseline } from "../src/baseline.js";
import type { Finding } from "../src/rules/types.js";

const dirs: string[] = [];

function tempFile(name: string): string {
  const dir = mkdtempSync(join(tmpdir(), "skillcanary-"));
  dirs.push(dir);
  return join(dir, name);
}

function finding(ruleId: string, line: number): Finding {
  return {
    ruleId,
    severity: "high",
    confidence: "high",
    message: "message can change",
    file: "SKILL.md",
    line,
  };
}

afterEach(() => {
  for (const dir of dirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("baseline", () => {
  it("writes unique fingerprints and reads them back", () => {
    const path = tempFile("baseline.json");
    const count = writeBaseline(path, [
      finding("sec.env-read", 3),
      finding("sec.env-read", 3),
      finding("inj.ignore-previous", 1),
    ]);
    expect(count).toBe(2);
    const loaded = loadBaseline(path);
    expect(loaded.has(fingerprint(finding("sec.env-read", 3)))).toBe(true);
    expect(loaded.has(fingerprint(finding("inj.ignore-previous", 2)))).toBe(false);
  });

  it("rejects a malformed baseline", () => {
    const path = tempFile("baseline.json");
    writeBaseline(path, []);
    const contents = JSON.parse(readFileSync(path, "utf8"));
    contents.findings = "nope";
    writeFileSync(path, JSON.stringify(contents));
    expect(() => loadBaseline(path)).toThrow(/findings array/);
  });
});
