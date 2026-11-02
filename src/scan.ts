import { existsSync, readFileSync } from "node:fs";
import { basename, join } from "node:path";
import { isMcpFile } from "./inputs/mcp.js";
import {
  isInsideSkillDir,
  isScriptFile,
  isSkillFile,
  parseSkillFrontmatter,
  skillDirs,
} from "./inputs/skills.js";
import { readText, walkFiles } from "./inputs/walk.js";
import type { McpServer } from "./mcp/model.js";
import { parseMcpConfig } from "./mcp/parse.js";
import { runRules, selectRules } from "./rules/registry.js";
import { SEVERITY_ORDER } from "./rules/types.js";
import type { FileEntry, FileKind, Finding } from "./rules/types.js";
import { looksBinary } from "./util/text.js";

export interface ScanOptions {
  /** Restrict to these rule IDs (all rules when omitted or empty). */
  rules?: string[];
}

function isAgentConfigFile(relativePath: string): boolean {
  const lower = relativePath.toLowerCase();
  return (
    /(?:^|\/)\.claude\/settings(?:\.local)?\.json$/.test(lower) ||
    /(?:^|\/)\.claude\/hooks\/hooks\.json$/.test(lower)
  );
}

const INSTRUCTION_FILENAMES = new Set([
  "claude.md",
  "agents.md",
  "gemini.md",
  ".cursorrules",
  ".windsurfrules",
  ".clinerules",
]);

function isInstructionsFile(relativePath: string): boolean {
  const lower = relativePath.toLowerCase();
  if (INSTRUCTION_FILENAMES.has(basename(lower))) {
    return true;
  }
  if (/(?:^|\/)\.cursor\/rules\/.*\.mdc$/.test(lower)) {
    return true;
  }
  return /(?:^|\/)\.github\/copilot-instructions\.md$/.test(lower);
}

function classify(relativePath: string, dirs: Set<string>): FileKind {
  if (isSkillFile(relativePath)) {
    return "skill";
  }
  if (isMcpFile(relativePath)) {
    return "mcp";
  }
  if (isAgentConfigFile(relativePath)) {
    return "agentconfig";
  }
  if (basename(relativePath).toLowerCase() === "package.json") {
    return "config";
  }
  if (isInstructionsFile(relativePath)) {
    return "instructions";
  }
  if (isScriptFile(relativePath) && isInsideSkillDir(relativePath, dirs)) {
    return "script";
  }
  return "other";
}

/** Read `.scannerignore` (one path prefix per line; `#` comments allowed). */
function readIgnores(root: string): string[] {
  const ignorePath = join(root, ".scannerignore");
  if (!existsSync(ignorePath)) {
    return [];
  }
  return readFileSync(ignorePath, "utf8")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const bySeverity = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
    if (bySeverity !== 0) {
      return bySeverity;
    }
    if (a.file !== b.file) {
      return a.file < b.file ? -1 : 1;
    }
    return (a.line ?? 0) - (b.line ?? 0);
  });
}

function buildEntry(path: string, kind: FileKind, content: string): FileEntry {
  const entry: FileEntry = { path, kind, content, lines: content.split(/\r?\n/) };
  if (kind === "mcp") {
    entry.mcp = parseMcpConfig(content, path);
  }
  if (kind === "skill") {
    entry.skill = parseSkillFrontmatter(content);
  }
  return entry;
}

/** Run the rules over prepared entries (used by local and remote scans). */
export function evaluate(entries: FileEntry[], options: ScanOptions = {}): Finding[] {
  return sortFindings(runRules(entries, selectRules(options.rules)));
}

/** Build an entry for a live remote MCP server discovered over the network. */
export function remoteEntry(server: McpServer): FileEntry {
  let host = server.url ?? server.name;
  try {
    host = server.url ? new URL(server.url).host : server.name;
  } catch {
    // keep the fallback
  }
  return {
    path: `mcp://${host}`,
    kind: "mcp",
    content: "",
    lines: [],
    mcp: { servers: [server] },
  };
}

/** Scan a directory and return findings, highest severity first. */
export function scan(root: string, options: ScanOptions = {}): Finding[] {
  const files = walkFiles(root, readIgnores(root));
  const dirs = skillDirs(files);
  const entries: FileEntry[] = [];

  for (const path of files) {
    const kind = classify(path, dirs);
    if (kind === "other") {
      continue;
    }
    let content: string;
    try {
      content = readText(root, path);
    } catch {
      continue;
    }
    if (looksBinary(content)) {
      continue;
    }
    entries.push(buildEntry(path, kind, content));
  }

  return evaluate(entries, options);
}

/** Scan a single MCP config file anywhere on disk (used by `--mcp-config`). */
export function scanMcpFile(filePath: string, options: ScanOptions = {}): Finding[] {
  const content = readFileSync(filePath, "utf8");
  return evaluate([buildEntry(filePath, "mcp", content)], options);
}

/** Collect every MCP server declared under a directory. */
export function collectMcpServers(root: string): McpServer[] {
  const servers: McpServer[] = [];
  for (const path of walkFiles(root, readIgnores(root))) {
    if (!isMcpFile(path)) {
      continue;
    }
    let content: string;
    try {
      content = readText(root, path);
    } catch {
      continue;
    }
    servers.push(...parseMcpConfig(content, path).servers);
  }
  return servers;
}

/** Collect MCP servers declared in a single config file. */
export function collectMcpServersFromFile(filePath: string): McpServer[] {
  return parseMcpConfig(readFileSync(filePath, "utf8"), filePath).servers;
}
