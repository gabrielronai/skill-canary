import { describe, expect, it } from "vitest";
import { scan } from "../src/scan.js";

describe("fixtures", () => {
  it("finds the expected rule IDs in the malicious fixture", () => {
    const ids = new Set(scan("test/fixtures/malicious").map((finding) => finding.ruleId));
    expect(ids.has("inj.ignore-previous")).toBe(true);
    expect(ids.has("sec.env-read")).toBe(true);
  });

  it("reports nothing for the clean fixture", () => {
    expect(scan("test/fixtures/clean")).toHaveLength(0);
  });
});
