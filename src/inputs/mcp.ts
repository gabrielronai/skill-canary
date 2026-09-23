import { basename } from "node:path";

/** Config filenames that describe MCP servers. */
export const MCP_FILENAMES = new Set([
  ".mcp.json",
  "mcp.json",
  "claude_desktop_config.json",
  "mcpize.yaml",
  "mcpize.yml",
  "mcp_config.json", // Windsurf
  "cline_mcp_settings.json", // Cline
]);

/** Directories whose MCP config uses a generic filename. */
const NESTED_DIRS = ["/.vscode/", "/.cursor/", "/.claude/", "/.continue/", "/.codeium/windsurf/"];

function toPosix(path: string): string {
  return path.split("\\").join("/");
}

export function isMcpFile(relativePath: string): boolean {
  const name = basename(relativePath).toLowerCase();
  const path = toPosix(relativePath).toLowerCase();
  if (MCP_FILENAMES.has(name)) {
    return true;
  }
  const nested = NESTED_DIRS.some((dir) => path.includes(dir));
  return nested && (name === "mcp.json" || name === "mcp_config.json");
}
