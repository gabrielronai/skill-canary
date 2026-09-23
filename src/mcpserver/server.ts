import { createInterface } from "node:readline";
import { TOOL_NAME, TOOL_VERSION } from "../version.js";
import {
  type ToolOutcome,
  explainRuleTool,
  listRulesTool,
  scanConfigTool,
  scanPackageTool,
  scanPathTool,
  scanRemoteTool,
} from "./tools.js";

const PROTOCOL_VERSION = "2025-06-18";

interface JsonRpcMessage {
  jsonrpc: string;
  id?: number | string | null;
  method: string;
  params?: unknown;
}

export const TOOL_DEFINITIONS = [
  {
    name: "scan_path",
    description: "Scan a directory for risky SKILL.md skills and MCP configs.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Directory to scan." },
        rules: { type: "string", description: "Comma-separated rule IDs (all by default)." },
        failOn: { type: "string", description: "Severity threshold; sets wouldFail." },
      },
      required: ["path"],
    },
  },
  {
    name: "scan_mcp_config",
    description: "Scan a single MCP config file.",
    inputSchema: {
      type: "object",
      properties: {
        file: { type: "string", description: "Path to an MCP config file." },
        rules: { type: "string", description: "Comma-separated rule IDs (all by default)." },
      },
      required: ["file"],
    },
  },
  {
    name: "scan_package",
    description: "Resolve and scan an npm package or local directory (never executes it).",
    inputSchema: {
      type: "object",
      properties: { spec: { type: "string", description: "Package spec or local path." } },
      required: ["spec"],
    },
  },
  {
    name: "scan_remote_mcp",
    description: "Live-scan a remote MCP endpoint (initialize + tools/list). SSRF-guarded.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "Remote MCP URL." },
        allowInsecure: { type: "boolean", description: "Allow http:// and private hosts." },
      },
      required: ["url"],
    },
  },
  {
    name: "list_rules",
    description: "List the available rules.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "explain_rule",
    description: "Explain one rule by ID.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string", description: "Rule ID." } },
      required: ["id"],
    },
  },
];

function respond(id: JsonRpcMessage["id"], result: unknown): Record<string, unknown> {
  return { jsonrpc: "2.0", id: id ?? null, result };
}

function errorResponse(
  id: JsonRpcMessage["id"],
  code: number,
  text: string,
): Record<string, unknown> {
  return { jsonrpc: "2.0", id: id ?? null, error: { code, message: text } };
}

function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" ? (value as Record<string, unknown>) : {};
}

function asString(value: unknown): string {
  return typeof value === "string" ? value : "";
}

async function callTool(
  id: JsonRpcMessage["id"],
  params: unknown,
): Promise<Record<string, unknown>> {
  const { name, arguments: args } = asRecord(params);
  const toolName = asString(name);
  const input = asRecord(args);

  let outcome: ToolOutcome;
  switch (toolName) {
    case "scan_path":
      outcome = scanPathTool({
        path: asString(input.path),
        rules: asString(input.rules) || undefined,
        failOn: asString(input.failOn) || undefined,
      });
      break;
    case "scan_mcp_config":
      outcome = scanConfigTool({
        file: asString(input.file),
        rules: asString(input.rules) || undefined,
      });
      break;
    case "scan_package":
      outcome = await scanPackageTool({ spec: asString(input.spec) });
      break;
    case "scan_remote_mcp":
      outcome = await scanRemoteTool({
        url: asString(input.url),
        allowInsecure: input.allowInsecure === true,
      });
      break;
    case "list_rules":
      outcome = listRulesTool();
      break;
    case "explain_rule":
      outcome = explainRuleTool(asString(input.id));
      break;
    default:
      return errorResponse(id, -32602, `Unknown tool: ${toolName}`);
  }

  return respond(id, {
    content: [{ type: "text", text: outcome.text }],
    ...(outcome.isError ? { isError: true } : {}),
  });
}

/** Handle one JSON-RPC message. Returns the response, or null for notifications. */
export async function handleRequest(
  message: JsonRpcMessage,
): Promise<Record<string, unknown> | null> {
  const id = message.id ?? null;
  const isNotification = message.id === undefined || message.id === null;

  switch (message.method) {
    case "initialize":
      return respond(id, {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: { tools: {} },
        serverInfo: { name: TOOL_NAME, version: TOOL_VERSION },
      });
    case "notifications/initialized":
      return null;
    case "ping":
      return respond(id, {});
    case "tools/list":
      return respond(id, { tools: TOOL_DEFINITIONS });
    case "tools/call":
      return callTool(id, message.params);
    default:
      return isNotification
        ? null
        : errorResponse(id, -32601, `Method not found: ${message.method}`);
  }
}

/** Run the MCP server over stdio until the client closes the stream. */
export async function startServer(): Promise<void> {
  const lines = createInterface({ input: process.stdin });
  lines.on("line", (line) => {
    const text = line.trim();
    if (!text) {
      return;
    }
    void (async () => {
      let response: Record<string, unknown> | null = null;
      try {
        const message = JSON.parse(text) as JsonRpcMessage;
        response = await handleRequest(message);
      } catch (error) {
        response = errorResponse(
          null,
          -32700,
          `Parse error: ${error instanceof Error ? error.message : error}`,
        );
      }
      if (response) {
        process.stdout.write(`${JSON.stringify(response)}\n`);
      }
    })();
  });
  await new Promise<void>((resolve) => lines.on("close", resolve));
}
