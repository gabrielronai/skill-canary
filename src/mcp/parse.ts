import { parse as parseYaml } from "yaml";
import type { McpConfig, McpServer, McpTool, McpTransport } from "./model.js";

function asRecord(value: unknown): Record<string, unknown> | null {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return null;
}

function toStringArray(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.map((entry) => (typeof entry === "string" ? entry : JSON.stringify(entry)));
  }
  if (typeof value === "string") {
    return [value];
  }
  return [];
}

function toStringRecord(value: unknown): Record<string, string> {
  const record = asRecord(value);
  if (!record) {
    return {};
  }
  const out: Record<string, string> = {};
  for (const [key, entry] of Object.entries(record)) {
    out[key] = typeof entry === "string" ? entry : JSON.stringify(entry);
  }
  return out;
}

function toTransport(entry: Record<string, unknown>): McpTransport {
  const type = typeof entry.type === "string" ? entry.type.toLowerCase() : undefined;
  if (type === "http" || type === "streamable-http" || type === "streamablehttp") {
    return "http";
  }
  if (type === "sse") {
    return "sse";
  }
  if (typeof entry.command === "string") {
    return "stdio";
  }
  if (typeof entry.url === "string") {
    return "http";
  }
  return "unknown";
}

export function collectSchemaText(value: unknown, depth = 0): string[] {
  if (depth > 6 || value === null) {
    return [];
  }
  if (typeof value === "string") {
    return [value];
  }
  if (Array.isArray(value)) {
    return value.flatMap((item) => collectSchemaText(item, depth + 1));
  }
  if (typeof value !== "object") {
    return [];
  }
  const out: string[] = [];
  for (const [key, item] of Object.entries(value)) {
    if (
      key === "description" ||
      key === "title" ||
      key === "default" ||
      key === "enum" ||
      key === "const" ||
      key === "examples"
    ) {
      out.push(...collectSchemaText(item, depth + 1));
    } else if (typeof item === "object") {
      out.push(...collectSchemaText(item, depth + 1));
    }
  }
  return out;
}

function toTools(value: unknown): McpTool[] {
  if (!Array.isArray(value)) {
    return [];
  }
  const tools: McpTool[] = [];
  for (const item of value) {
    const record = asRecord(item);
    if (!record) {
      continue;
    }
    const name = typeof record.name === "string" ? record.name : "";
    const description = typeof record.description === "string" ? record.description : undefined;
    const schemaText = collectSchemaText(record.inputSchema);
    const tool: McpTool = schemaText.length > 0 ? { name, schemaText } : { name };
    if (description !== undefined) {
      tool.description = description;
    }
    tools.push(tool);
  }
  return tools;
}

function lineOfServer(content: string, name: string): number | undefined {
  if (!name) {
    return undefined;
  }
  const lines = content.split(/\r?\n/);
  const index = lines.findIndex((line) => line.includes(`"${name}"`) || line.includes(`${name}:`));
  return index >= 0 ? index + 1 : undefined;
}

function toServer(name: string, value: unknown, content: string): McpServer {
  const entry = asRecord(value) ?? {};
  const description = typeof entry.description === "string" ? entry.description : undefined;
  const server: McpServer = {
    name,
    transport: toTransport(entry),
    args: toStringArray(entry.args),
    env: toStringRecord(entry.env),
    headers: toStringRecord(entry.headers),
    tools: toTools(entry.tools),
  };
  if (typeof entry.command === "string") {
    server.command = entry.command;
  }
  if (typeof entry.url === "string") {
    server.url = entry.url;
  }
  if (description !== undefined) {
    server.description = description;
  }
  const line = lineOfServer(content, name);
  if (line !== undefined) {
    server.line = line;
  }
  return server;
}

/** Parse an MCP config (JSON or YAML) into a normalized server list. */
export function parseMcpConfig(content: string, filename: string): McpConfig {
  const lower = filename.toLowerCase();
  let raw: unknown;
  try {
    raw =
      lower.endsWith(".yaml") || lower.endsWith(".yml") ? parseYaml(content) : JSON.parse(content);
  } catch (error) {
    return { servers: [], parseError: error instanceof Error ? error.message : String(error) };
  }

  const root = asRecord(raw);
  if (!root) {
    return { servers: [] };
  }
  const map = asRecord(root.mcpServers) ?? asRecord(root.servers);
  if (!map) {
    return { servers: [] };
  }

  const servers: McpServer[] = [];
  for (const [name, value] of Object.entries(map)) {
    servers.push(toServer(name, value, content));
  }
  return { servers };
}
