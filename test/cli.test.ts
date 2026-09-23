import { describe, expect, it } from "vitest";
import type { IO } from "../src/cli.js";
import { main } from "../src/cli.js";

function capture(): { io: IO; out: () => string; err: () => string } {
  let out = "";
  let err = "";
  return {
    io: {
      out: (text) => {
        out += text;
      },
      err: (text) => {
        err += text;
      },
    },
    out: () => out,
    err: () => err,
  };
}

describe("cli", () => {
  it("scans the malicious fixture and exits 1 at the high threshold", async () => {
    const { io, out } = capture();
    const code = await main(
      ["scan", "test/fixtures/malicious", "--fail-on", "high", "--no-color"],
      io,
    );
    expect(code).toBe(1);
    expect(out()).toContain("inj.ignore-previous");
    expect(out()).toContain("sec.env-read");
  });

  it("scans the clean fixture and exits 0", async () => {
    const { io } = capture();
    expect(await main(["scan", "test/fixtures/clean", "--no-color"], io)).toBe(0);
  });

  it("scans an MCP config via --mcp-config", async () => {
    const { io, out } = capture();
    const code = await main(
      [
        "scan",
        "test/fixtures/clean",
        "--mcp-config",
        "test-skills/mcp-env-secrets/mcp.json",
        "--no-color",
      ],
      io,
    );
    expect(code).toBe(1);
    expect(out()).toContain("mcp.secrets");
  });

  it("emits JSON with --format json", async () => {
    const { io, out } = capture();
    const code = await main(
      ["scan", "test/fixtures/malicious", "--format", "json", "--no-color"],
      io,
    );
    expect(code).toBe(1);
    const report = JSON.parse(out());
    expect(report.tool).toBe("skillcanary");
    expect(report.summary.total).toBeGreaterThan(0);
  });

  it("emits SARIF with --format sarif", async () => {
    const { io, out } = capture();
    await main(["scan", "test/fixtures/malicious", "--format", "sarif", "--no-color"], io);
    const sarif = JSON.parse(out());
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].results.length).toBeGreaterThan(0);
  });

  it("lists rules", async () => {
    const { io, out } = capture();
    expect(await main(["rules"], io)).toBe(0);
    expect(out()).toContain("mcp.imperative-desc");
  });

  it("returns 2 for a missing directory", async () => {
    const { io } = capture();
    expect(await main(["scan", "does/not/exist"], io)).toBe(2);
  });
});
