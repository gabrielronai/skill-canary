import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const pkg = JSON.parse(readFileSync("package.json", "utf8")) as {
  name?: string;
  version?: string;
  private?: boolean;
  license?: string;
  bin?: Record<string, string>;
  files?: string[];
  publishConfig?: { access?: string };
  scripts?: Record<string, string>;
};

describe("package publish readiness", () => {
  it("is not private and has the required metadata", () => {
    expect(pkg.private).toBeUndefined();
    expect(pkg.name).toBeTruthy();
    expect(pkg.version).toMatch(/^\d+\.\d+\.\d+$/);
    expect(pkg.license).toBe("Apache-2.0");
    expect(pkg.publishConfig?.access).toBe("public");
  });

  it("ships a bin, the dist output, and a prepublish build", () => {
    expect(Object.keys(pkg.bin ?? {}).length).toBeGreaterThan(0);
    expect(pkg.files).toContain("dist");
    expect(pkg.files).toContain("action.yml");
    expect(pkg.scripts?.prepublishOnly).toBeTruthy();
  });
});
