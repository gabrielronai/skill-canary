import { describe, expect, it } from "vitest";
import { handleRequest } from "../src/mcpserver/server.js";
import { scan } from "../src/scan.js";

type ToolList = { tools: { name: string }[] };
type ToolResult = { content: { text: string }[] };

describe("mcp server", () => {
  it("responds to initialize with server info", async () => {
    const response = await handleRequest({ jsonrpc: "2.0", id: 1, method: "initialize" });
    expect(response?.result).toMatchObject({ serverInfo: { name: "skillcanary" } });
  });

  it("lists the scan tools", async () => {
    const response = await handleRequest({ jsonrpc: "2.0", id: 2, method: "tools/list" });
    const names = ((response?.result as ToolList).tools ?? []).map((tool) => tool.name);
    expect(names).toContain("scan_path");
    expect(names).toContain("scan_mcp_config");
    expect(names).toContain("scan_package");
    expect(names).toContain("scan_remote_mcp");
  });

  it("runs scan_path on the malicious fixture", async () => {
    const response = await handleRequest({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "scan_path", arguments: { path: "test/fixtures/malicious" } },
    });
    const report = JSON.parse((response?.result as ToolResult).content[0]?.text ?? "{}");
    expect(report.tool).toBe("skillcanary");
    expect(report.findings.length).toBeGreaterThan(0);
  });

  it("returns a JSON-RPC error for an unknown tool", async () => {
    const response = await handleRequest({
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: { name: "nope", arguments: {} },
    });
    expect(response?.error).toBeTruthy();
  });

  it("ignores notifications", async () => {
    expect(await handleRequest({ jsonrpc: "2.0", method: "notifications/initialized" })).toBeNull();
  });
});

describe("shipped skill", () => {
  it("scans clean", () => {
    expect(scan("skills/skillcanary")).toHaveLength(0);
  });
});
