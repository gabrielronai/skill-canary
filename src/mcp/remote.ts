import { checkUrlSafety } from "../net/ssrf.js";
import type { McpServer, McpTool } from "./model.js";
import { collectSchemaText } from "./parse.js";

export interface RemoteOptions {
  headers?: Record<string, string>;
  timeoutMs?: number;
  allowInsecure?: boolean;
  allowPrivate?: boolean;
  maxBytes?: number;
  fetchImpl?: typeof fetch;
}

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_BYTES = 1_000_000;

function asRecord(value: unknown): Record<string, unknown> | null {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return null;
}

function rpcResult(json: unknown): Record<string, unknown> | null {
  return asRecord(asRecord(json)?.result);
}

function extractTools(json: unknown): McpTool[] {
  const result = rpcResult(json);
  const list = result && Array.isArray(result.tools) ? result.tools : [];
  const tools: McpTool[] = [];
  for (const item of list) {
    const record = asRecord(item);
    const name = record && typeof record.name === "string" ? record.name : "";
    if (!name) {
      continue;
    }
    const description =
      record && typeof record.description === "string" ? record.description : undefined;
    const schemaText = collectSchemaText(record?.inputSchema);
    const tool: McpTool = schemaText.length > 0 ? { name, schemaText } : { name };
    if (description !== undefined) {
      tool.description = description;
    }
    tools.push(tool);
  }
  return tools;
}

function serverName(json: unknown): string | undefined {
  const info = asRecord(rpcResult(json)?.serverInfo);
  return info && typeof info.name === "string" ? info.name : undefined;
}

function parseBody(text: string, contentType: string): unknown {
  if (contentType.includes("text/event-stream")) {
    for (const line of text.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (trimmed.startsWith("data:")) {
        const payload = trimmed.slice("data:".length).trim();
        if (payload) {
          try {
            return JSON.parse(payload);
          } catch {
            // keep scanning SSE frames
          }
        }
      }
    }
    throw new Error("no JSON in event-stream response");
  }
  return JSON.parse(text);
}

async function readCapped(response: Response, maxBytes: number): Promise<string> {
  const text = await response.text();
  if (Buffer.byteLength(text) > maxBytes) {
    throw new Error("response too large");
  }
  return text;
}

/**
 * Connect to a remote MCP server over Streamable HTTP, run `initialize` +
 * `tools/list`, and return the server with its tools. Never spawns a process.
 */
export async function fetchRemoteServer(
  rawUrl: string,
  options: RemoteOptions = {},
): Promise<McpServer> {
  const safety = await checkUrlSafety(rawUrl, {
    allowInsecure: options.allowInsecure,
    allowPrivate: options.allowPrivate,
  });
  if (!safety.ok) {
    throw new Error(`SSRF guard rejected URL: ${safety.reason}`);
  }

  const doFetch = options.fetchImpl ?? fetch;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  const baseHeaders: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
    ...(options.headers ?? {}),
  };

  const rpc = async (
    body: Record<string, unknown>,
    sessionId?: string,
  ): Promise<{ json: unknown; session: string | null }> => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await doFetch(rawUrl, {
        method: "POST",
        headers: sessionId ? { ...baseHeaders, "mcp-session-id": sessionId } : baseHeaders,
        body: JSON.stringify(body),
        signal: controller.signal,
        redirect: "manual",
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const session = response.headers.get("mcp-session-id");
      const text = await readCapped(response, maxBytes);
      return { json: parseBody(text, response.headers.get("content-type") ?? ""), session };
    } finally {
      clearTimeout(timer);
    }
  };

  const init = await rpc({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "skillcanary", version: "0.0.0" },
    },
  });

  const session = init.session ?? undefined;
  try {
    await rpc({ jsonrpc: "2.0", method: "notifications/initialized" }, session);
  } catch {
    // The notification is best-effort; some servers reject it.
  }

  const list = await rpc({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }, session);
  const host = new URL(rawUrl).host;
  const name = serverName(init.json) ?? host;

  return {
    name,
    transport: "http",
    url: rawUrl,
    headers: options.headers ?? {},
    args: [],
    env: {},
    tools: extractTools(list.json),
  };
}
