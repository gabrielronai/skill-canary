import { createServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { fetchRemoteServer } from "../src/mcp/remote.js";

let server: Server | undefined;
let port = 0;

function handler(request: IncomingMessage, response: ServerResponse): void {
  let body = "";
  request.on("data", (chunk) => {
    body += chunk;
  });
  request.on("end", () => {
    const message = JSON.parse(body || "{}") as { id?: number; method?: string };
    if (message.method === "initialize") {
      response.setHeader("content-type", "application/json");
      response.setHeader("mcp-session-id", "sess-1");
      response.end(
        JSON.stringify({
          jsonrpc: "2.0",
          id: message.id,
          result: {
            protocolVersion: "2025-06-18",
            serverInfo: { name: "mock-server", version: "1.0.0" },
          },
        }),
      );
    } else if (message.method === "notifications/initialized") {
      response.statusCode = 202;
      response.end();
    } else if (message.method === "tools/list") {
      response.setHeader("content-type", "application/json");
      response.end(
        JSON.stringify({
          jsonrpc: "2.0",
          id: message.id,
          result: { tools: [{ name: "echo", description: "Echoes the input." }] },
        }),
      );
    } else {
      response.statusCode = 404;
      response.end();
    }
  });
}

beforeAll(async () => {
  server = createServer(handler);
  await new Promise<void>((resolve) => {
    server?.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  port = typeof address === "object" && address ? address.port : 0;
});

afterAll(() => {
  server?.close();
});

describe("fetchRemoteServer", () => {
  it("lists tools over Streamable HTTP", async () => {
    const result = await fetchRemoteServer(`http://127.0.0.1:${port}/mcp`, {
      allowInsecure: true,
      allowPrivate: true,
    });
    expect(result.name).toBe("mock-server");
    expect(result.tools.map((tool) => tool.name)).toContain("echo");
  });

  it("refuses a private host unless allowPrivate is set", async () => {
    await expect(
      fetchRemoteServer(`http://127.0.0.1:${port}/mcp`, { allowInsecure: true }),
    ).rejects.toThrow(/SSRF/);
  });
});
