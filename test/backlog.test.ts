import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { ALL_RULE_IDS } from "../src/rules/registry.js";

const BACKLOG = new URL("../docs/rule-backlog.md", import.meta.url);
const ROW_RE = /^\|\s*`([a-z][a-z0-9-]*\.[a-z0-9-]+)`\s*\|/;

function candidateIds(): string[] {
  const ids: string[] = [];
  for (const line of readFileSync(BACKLOG, "utf8").split(/\r?\n/)) {
    const match = ROW_RE.exec(line);
    if (match?.[1]) {
      ids.push(match[1]);
    }
  }
  return ids;
}

describe("rule backlog", () => {
  it("has unique candidate IDs that do not collide with shipped rules", () => {
    const ids = candidateIds();
    expect(ids.length).toBeGreaterThan(0);
    const live = new Set(ALL_RULE_IDS);
    expect(ids.filter((id) => live.has(id))).toEqual([]);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
