import { existsSync, statSync } from "node:fs";
import type { McpServer } from "./mcp/model.js";
import { fetchRemoteServer } from "./mcp/remote.js";
import { scanPackage } from "./packages/scan.js";
import { packageSpecFromServer } from "./packages/spec.js";
import { formatJson } from "./report/json.js";
import { formatSarif } from "./report/sarif.js";
import { formatText } from "./report/text.js";
import { ALL_RULES, ALL_RULE_IDS } from "./rules/registry.js";
import type { FailThreshold, Finding } from "./rules/types.js";
import { meetsThreshold } from "./rules/types.js";
import {
  collectMcpServers,
  collectMcpServersFromFile,
  evaluate,
  remoteEntry,
  scan,
  scanMcpFile,
  sortFindings,
} from "./scan.js";
import { TOOL_VERSION } from "./version.js";

export interface IO {
  out: (text: string) => void;
  err: (text: string) => void;
}

const DEFAULT_IO: IO = {
  out: (text) => process.stdout.write(text),
  err: (text) => process.stderr.write(text),
};

const SEVERITIES: FailThreshold[] = ["none", "critical", "high", "medium", "low", "info"];
const FORMATS = new Set(["text", "json", "sarif"]);

const HELP = `skillcanary — security scanner for MCP servers and SKILL.md skills

Usage:
  skillcanary scan [path]        Scan a directory (default: .)
  skillcanary rules              List available rules
  skillcanary explain <rule-id>  Explain a rule
  skillcanary mcp                Run the MCP server over stdio (for AI agents)

Options:
  --mcp-config <file>          Also scan a specific MCP config file (repeatable)
  --mcp-url <url>              Also scan a remote MCP server live (repeatable)
  --mcp-remote                 Live-scan remote servers found in configs
  --mcp-header "K: V"          Header for remote scans (repeatable)
  --allow-insecure             Allow http:// and private hosts (local testing)
  --package <spec>             Scan an npm package or local dir (repeatable)
  --scan-packages              Scan packages referenced by MCP servers
  --package-max-mb <n>         Max package download size (default: 10)
  --format <text|json|sarif>   Output format (default: text)
  --fail-on <level>            Exit 1 at or above: none|critical|high|medium|low|info
                               (default: high)
  --rules <id,id>              Only run these rules
  --no-color                   Disable colored output
  --quiet                      Suppress the report (exit code only)
  -h, --help                   Show help
  -v, --version                Show version
`;

interface ScanArgs {
  path: string;
  format: string;
  failOn: FailThreshold;
  color: boolean;
  quiet: boolean;
  rules?: string[];
  mcpConfigs: string[];
  mcpUrls: string[];
  mcpHeaders: Record<string, string>;
  mcpRemote: boolean;
  allowInsecure: boolean;
  packages: string[];
  scanPackages: boolean;
  packageMaxBytes: number;
}

function parseHeader(value: string): [string, string] | null {
  const index = value.indexOf(":");
  if (index <= 0) {
    return null;
  }
  return [value.slice(0, index).trim(), value.slice(index + 1).trim()];
}

function parseScanArgs(argv: string[], io: IO): ScanArgs | null {
  const parsed: ScanArgs = {
    path: ".",
    format: "text",
    failOn: "high",
    color: Boolean(process.stdout.isTTY),
    quiet: false,
    mcpConfigs: [],
    mcpUrls: [],
    mcpHeaders: {},
    mcpRemote: false,
    allowInsecure: false,
    packages: [],
    scanPackages: false,
    packageMaxBytes: 10 * 1024 * 1024,
  };
  const positionals: string[] = [];

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    switch (arg) {
      case "--format":
        parsed.format = argv[++index] ?? "";
        break;
      case "--fail-on": {
        const value = argv[++index] ?? "";
        if (!SEVERITIES.includes(value as FailThreshold)) {
          io.err(`Invalid --fail-on value: ${value}\n`);
          return null;
        }
        parsed.failOn = value as FailThreshold;
        break;
      }
      case "--rules": {
        const value = argv[++index] ?? "";
        parsed.rules = value
          .split(",")
          .map((rule) => rule.trim())
          .filter(Boolean);
        break;
      }
      case "--mcp-config": {
        const value = argv[++index] ?? "";
        if (!value) {
          io.err("--mcp-config requires a file path\n");
          return null;
        }
        parsed.mcpConfigs.push(value);
        break;
      }
      case "--mcp-url": {
        const value = argv[++index] ?? "";
        if (!value) {
          io.err("--mcp-url requires a URL\n");
          return null;
        }
        parsed.mcpUrls.push(value);
        break;
      }
      case "--mcp-header": {
        const value = argv[++index] ?? "";
        const header = parseHeader(value);
        if (!header) {
          io.err(`Invalid --mcp-header (expected "Name: Value"): ${value}\n`);
          return null;
        }
        parsed.mcpHeaders[header[0]] = header[1];
        break;
      }
      case "--mcp-remote":
        parsed.mcpRemote = true;
        break;
      case "--allow-insecure":
        parsed.allowInsecure = true;
        break;
      case "--package": {
        const value = argv[++index] ?? "";
        if (!value) {
          io.err("--package requires a package spec or path\n");
          return null;
        }
        parsed.packages.push(value);
        break;
      }
      case "--scan-packages":
        parsed.scanPackages = true;
        break;
      case "--package-max-mb": {
        const value = Number(argv[++index] ?? "");
        if (!Number.isFinite(value) || value <= 0) {
          io.err("--package-max-mb requires a positive number\n");
          return null;
        }
        parsed.packageMaxBytes = Math.floor(value * 1024 * 1024);
        break;
      }
      case "--no-color":
        parsed.color = false;
        break;
      case "--quiet":
        parsed.quiet = true;
        break;
      default:
        if (arg.startsWith("-")) {
          io.err(`Unknown option: ${arg}\n`);
          return null;
        }
        positionals.push(arg);
    }
  }

  if (positionals[0]) {
    parsed.path = positionals[0];
  }
  return parsed;
}

function pathHint(io: IO, path: string): void {
  if (path.includes("$env:") || path.includes("%USERPROFILE%")) {
    io.err(
      "Hint: the shell did not expand the variable. Use $HOME (PowerShell/bash) " +
        "or %USERPROFILE% (cmd.exe), inside double quotes.\n",
    );
  }
}

async function scanRemote(url: string, args: ScanArgs, io: IO): Promise<Finding[] | null> {
  try {
    const server: McpServer = await fetchRemoteServer(url, {
      headers: args.mcpHeaders,
      allowInsecure: args.allowInsecure,
      allowPrivate: args.allowInsecure,
    });
    return evaluate([remoteEntry(server)], { rules: args.rules });
  } catch (error) {
    io.err(`Remote scan failed for ${url}: ${error instanceof Error ? error.message : error}\n`);
    return null;
  }
}

async function runScan(argv: string[], io: IO): Promise<number> {
  const args = parseScanArgs(argv, io);
  if (args === null) {
    return 2;
  }
  if (!FORMATS.has(args.format)) {
    io.err(`Invalid --format value: ${args.format} (use text, json, or sarif)\n`);
    return 2;
  }

  const findings: Finding[] = [];
  const pathIsDir = existsSync(args.path) && statSync(args.path).isDirectory();
  if (pathIsDir) {
    findings.push(...scan(args.path, { rules: args.rules }));
  } else if (args.mcpConfigs.length === 0 && args.mcpUrls.length === 0 && !args.mcpRemote) {
    io.err(`Not a directory: ${args.path}\n`);
    pathHint(io, args.path);
    return 2;
  }

  for (const config of args.mcpConfigs) {
    if (!existsSync(config) || !statSync(config).isFile()) {
      io.err(`Not a file: ${config}\n`);
      return 2;
    }
    findings.push(...scanMcpFile(config, { rules: args.rules }));
  }

  const urls = new Set(args.mcpUrls);
  if (args.mcpRemote) {
    const servers: McpServer[] = [];
    if (pathIsDir) {
      servers.push(...collectMcpServers(args.path));
    }
    for (const config of args.mcpConfigs) {
      servers.push(...collectMcpServersFromFile(config));
    }
    for (const server of servers) {
      if (server.url) {
        urls.add(server.url);
      }
    }
  }

  for (const url of urls) {
    const remoteFindings = await scanRemote(url, args, io);
    if (remoteFindings === null) {
      return 2;
    }
    findings.push(...remoteFindings);
  }

  const packageSpecs = new Set(args.packages);
  if (args.scanPackages) {
    const servers: McpServer[] = [];
    if (pathIsDir) {
      servers.push(...collectMcpServers(args.path));
    }
    for (const config of args.mcpConfigs) {
      servers.push(...collectMcpServersFromFile(config));
    }
    for (const server of servers) {
      const spec = packageSpecFromServer(server);
      if (spec) {
        packageSpecs.add(spec);
      }
    }
  }
  for (const spec of packageSpecs) {
    try {
      findings.push(
        ...(await scanPackage(spec, { rules: args.rules, maxBytes: args.packageMaxBytes })),
      );
    } catch (error) {
      io.err(
        `Package scan failed for ${spec}: ${error instanceof Error ? error.message : error}\n`,
      );
      return 2;
    }
  }

  const sorted = sortFindings(findings);
  if (!args.quiet) {
    if (args.format === "json") {
      io.out(formatJson(sorted));
    } else if (args.format === "sarif") {
      io.out(formatSarif(sorted));
    } else {
      io.out(formatText(sorted, { color: args.color }));
    }
  }
  return sorted.some((finding) => meetsThreshold(finding.severity, args.failOn)) ? 1 : 0;
}

function listRules(io: IO): void {
  const lines = ALL_RULES.map(
    (rule) => `${rule.severity.padEnd(8)} ${rule.id.padEnd(22)} ${rule.description}`,
  );
  io.out(`${lines.join("\n")}\n`);
}

function explainRule(id: string | undefined, io: IO): number {
  const rule = ALL_RULES.find((candidate) => candidate.id === id);
  if (!rule) {
    io.err(`Unknown rule: ${id ?? "(none)"}\nKnown rules: ${ALL_RULE_IDS.join(", ")}\n`);
    return 2;
  }
  io.out(
    `${rule.id}\nseverity: ${rule.severity}\nconfidence: ${rule.confidence}\n\n${rule.description}\n`,
  );
  return 0;
}

/** CLI entry point. Resolves to the process exit code. */
export async function main(argv: string[], io: IO = DEFAULT_IO): Promise<number> {
  if (argv.length === 0 || argv.includes("--help") || argv.includes("-h")) {
    io.out(HELP);
    return 0;
  }
  if (argv.includes("--version") || argv.includes("-v")) {
    io.out(`${TOOL_VERSION}\n`);
    return 0;
  }

  const [command, ...rest] = argv;
  switch (command) {
    case "scan":
      return runScan(rest, io);
    case "rules":
      listRules(io);
      return 0;
    case "explain":
      return explainRule(rest[0], io);
    case "mcp": {
      const { startServer } = await import("./mcpserver/server.js");
      await startServer();
      return 0;
    }
    default:
      io.err(`Unknown command: ${command}\n\n${HELP}`);
      return 2;
  }
}
