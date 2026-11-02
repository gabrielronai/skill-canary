import { readFileSync, writeFileSync } from "node:fs";
import type { Finding } from "./rules/types.js";

/** Stable identity of a finding across runs; messages may be reworded. */
export function fingerprint(finding: Finding): string {
  return `${finding.ruleId}|${finding.file}|${finding.line ?? ""}`;
}

export function loadBaseline(path: string): Set<string> {
  const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
  const findings = (parsed as { findings?: unknown } | null)?.findings;
  if (!Array.isArray(findings)) {
    throw new Error("baseline must be an object with a findings array");
  }
  return new Set(findings.filter((value): value is string => typeof value === "string"));
}

export function writeBaseline(path: string, findings: Finding[]): number {
  const entries = [...new Set(findings.map(fingerprint))].sort();
  writeFileSync(path, `${JSON.stringify({ version: 1, findings: entries }, null, 2)}\n`);
  return entries.length;
}
