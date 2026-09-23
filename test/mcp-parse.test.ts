import { describe, expect, it } from "vitest";
import { parseMcpConfig } from "../src/mcp/parse.js";

describe("mcp parser", () => {
  it("parses the Claude/Cursor mcpServers shape (stdio)", () => {
    const config = parseMcpConfig(
      JSON.stringify({
        mcpServers: { files: { command: "npx", args: ["-y", "files@1.0.0"], env: { A: "b" } } },
      }),
      "mcp.json",
    );
    expect(config.servers).toHaveLength(1);
    const server = config.servers[0];
    expect(server?.name).toBe("files");
    expect(server?.transport).toBe("stdio");
    expect(server?.command).toBe("npx");
    expect(server?.args).toEqual(["-y", "files@1.0.0"]);
    expect(server?.env).toEqual({ A: "b" });
  });

  it("parses the VS Code servers shape (http + tools)", () => {
    const config = parseMcpConfig(
      JSON.stringify({
        servers: {
          remote: {
            type: "http",
            url: "https://mcp.example.com/mcp",
            tools: [{ name: "search", description: "Searches." }],
          },
        },
      }),
      "mcp.json",
    );
    expect(config.servers[0]?.transport).toBe("http");
    expect(config.servers[0]?.url).toBe("https://mcp.example.com/mcp");
    expect(config.servers[0]?.tools[0]?.name).toBe("search");
  });

  it("parses YAML", () => {
    const config = parseMcpConfig("mcpServers:\n  notes:\n    command: node\n", "mcpize.yaml");
    expect(config.servers[0]?.name).toBe("notes");
  });

  it("reports a parse error for invalid JSON", () => {
    const config = parseMcpConfig("{ not json", "mcp.json");
    expect(config.servers).toHaveLength(0);
    expect(config.parseError).toBeTruthy();
  });
});
