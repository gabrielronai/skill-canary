/** MCP domain model, shared by the parser, rules, and the live client. */

export type McpTransport = "stdio" | "http" | "sse" | "unknown";

export interface McpTool {
  name: string;
  description?: string;
  /** Strings collected from the tool's input schema (descriptions, defaults, enums). */
  schemaText?: string[];
}

export interface McpServer {
  name: string;
  transport: McpTransport;
  command?: string;
  args: string[];
  env: Record<string, string>;
  url?: string;
  headers: Record<string, string>;
  description?: string;
  tools: McpTool[];
  /** 1-based line of the server name in the source file, when known. */
  line?: number;
}

export interface McpConfig {
  servers: McpServer[];
  /** Set when the content could not be parsed as JSON/YAML. */
  parseError?: string;
}
