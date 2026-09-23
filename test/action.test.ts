import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";

const action = parse(readFileSync("action.yml", "utf8")) as {
  name?: string;
  description?: string;
  runs?: { using?: string; steps?: unknown[] };
  inputs?: Record<string, unknown>;
  outputs?: Record<string, unknown>;
};

describe("action.yml", () => {
  it("is a composite action with required metadata", () => {
    expect(action.name).toBeTruthy();
    expect(action.description).toBeTruthy();
    expect(action.runs?.using).toBe("composite");
    expect(Array.isArray(action.runs?.steps)).toBe(true);
  });

  it("declares the documented inputs and the report output", () => {
    for (const key of ["path", "format", "fail-on", "rules", "sarif-file", "upload-sarif"]) {
      expect(action.inputs?.[key], `input ${key}`).toBeTruthy();
    }
    expect(action.outputs?.["sarif-file"]).toBeTruthy();
  });
});
