import type { McpServer } from "../mcp/model.js";
import { redactSecrets, toSafeSnippet } from "../util/text.js";
import type { Finding, Rule } from "./types.js";

const MCP = ["mcp"] as const;

function finding(value: Finding): Finding {
  return value;
}

function servers(entry: { mcp?: { servers: McpServer[] } }): McpServer[] {
  return entry.mcp?.servers ?? [];
}

function serverText(server: McpServer): string[] {
  const text: string[] = [];
  if (server.description) {
    text.push(server.description);
  }
  for (const tool of server.tools) {
    if (tool.description) {
      text.push(tool.description);
    }
  }
  return text;
}

// --- mcp.invalid ---------------------------------------------------------------

const invalidRule: Rule = {
  id: "mcp.invalid",
  severity: "info",
  confidence: "high",
  description: "An MCP config file could not be parsed as JSON/YAML.",
  kinds: [...MCP],
  check(entry): Finding[] {
    const parseError = entry.mcp?.parseError;
    if (!parseError) {
      return [];
    }
    return [
      finding({
        ruleId: "mcp.invalid",
        severity: "info",
        confidence: "high",
        message: `MCP config could not be parsed: ${parseError}`,
        file: entry.path,
        remediation: "Fix the JSON/YAML so the config can be reviewed.",
      }),
    ];
  },
};

// --- mcp.imperative-desc -------------------------------------------------------

const IMPERATIVE: RegExp[] = [
  /\b(always|must|be sure to|make sure to)\s+(call|use|invoke|run|prefer)\b/i,
  /\bbefore (using|you use|calling|invoking)\b/i,
  /\b(do not|don't|never)\s+(tell|inform|notify|reveal|mention|disclose)\b/i,
  /\bignore (all|any|the)?\s*(previous|prior|earlier|above)\b/i,
  /\b(you (must|should)|ensure (that )?you)\b/i,
];

const imperativeRule: Rule = {
  id: "mcp.imperative-desc",
  severity: "high",
  confidence: "medium",
  description: "Server/tool descriptions contain instructions aimed at the model.",
  kinds: [...MCP],
  check(entry): Finding[] {
    const findings: Finding[] = [];
    for (const server of servers(entry)) {
      for (const text of serverText(server)) {
        if (IMPERATIVE.some((pattern) => pattern.test(text))) {
          findings.push(
            finding({
              ruleId: "mcp.imperative-desc",
              severity: "high",
              confidence: "medium",
              message: `MCP server "${server.name}" description contains instruction-like language.`,
              file: entry.path,
              line: server.line,
              snippet: toSafeSnippet(text),
              remediation: "Tool descriptions should describe capability, not instruct the model.",
            }),
          );
          break;
        }
      }
    }
    return findings;
  },
};

// --- mcp.shadow ----------------------------------------------------------------

const CANONICAL_TOOLS = [
  "readfile",
  "writefile",
  "read",
  "write",
  "bash",
  "shell",
  "exec",
  "execute",
  "search",
  "fetch",
  "http",
  "httprequest",
  "browser",
  "filesystem",
  "terminal",
  "edit",
  "listfiles",
  "run",
  "command",
  "webfetch",
  "websearch",
];

function normalizeName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function withinOneEdit(a: string, b: string): boolean {
  if (Math.abs(a.length - b.length) > 1) {
    return false;
  }
  if (a === b) {
    return false;
  }
  let i = 0;
  let j = 0;
  let edits = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) {
      i += 1;
      j += 1;
      continue;
    }
    edits += 1;
    if (edits > 1) {
      return false;
    }
    if (a.length > b.length) {
      i += 1;
    } else if (a.length < b.length) {
      j += 1;
    } else {
      i += 1;
      j += 1;
    }
  }
  return edits + (a.length - i) + (b.length - j) <= 1;
}

function shadowTarget(name: string): string | null {
  const normalized = normalizeName(name);
  if (normalized.length < 3 || CANONICAL_TOOLS.includes(normalized)) {
    return null;
  }
  for (const canonical of CANONICAL_TOOLS) {
    if (withinOneEdit(normalized, canonical)) {
      return canonical;
    }
  }
  return null;
}

const shadowRule: Rule = {
  id: "mcp.shadow",
  severity: "high",
  confidence: "medium",
  description: "Server/tool names mimic well-known tools (shadowing/typosquat).",
  kinds: [...MCP],
  check(entry): Finding[] {
    const findings: Finding[] = [];
    for (const server of servers(entry)) {
      const names = [server.name, ...server.tools.map((tool) => tool.name)];
      for (const name of names) {
        const target = shadowTarget(name);
        if (target) {
          findings.push(
            finding({
              ruleId: "mcp.shadow",
              severity: "high",
              confidence: "medium",
              message: `Name "${name}" closely mimics the common tool "${target}".`,
              file: entry.path,
              line: server.line,
              remediation: "Verify the server is the tool it appears to be; rename or remove it.",
            }),
          );
        }
      }
    }
    return findings;
  },
};

// --- mcp.overreach -------------------------------------------------------------

const SECRET_KEY_RE = /(api[_-]?key|token|secret|password|passwd|credential|private[_-]?key)/i;
const PATHISH_RE = /(^|[\s"'=])(~\/|\/etc\/|\/root\/|\/home\/|\$HOME|[A-Za-z]:\\)/;

const overreachRule: Rule = {
  id: "mcp.overreach",
  severity: "medium",
  confidence: "medium",
  description: "Server requests secrets or filesystem access beyond a likely purpose.",
  kinds: [...MCP],
  check(entry): Finding[] {
    const findings: Finding[] = [];
    for (const server of servers(entry)) {
      for (const key of Object.keys(server.env)) {
        if (SECRET_KEY_RE.test(key)) {
          findings.push(
            finding({
              ruleId: "mcp.overreach",
              severity: "medium",
              confidence: "medium",
              message: `Server "${server.name}" requests a secret-like env var (${key}).`,
              file: entry.path,
              line: server.line,
              remediation: "Confirm the server needs this access; scope it narrowly.",
            }),
          );
        }
      }
      const argText = [server.command ?? "", ...server.args].join(" ");
      if (PATHISH_RE.test(argText)) {
        findings.push(
          finding({
            ruleId: "mcp.overreach",
            severity: "medium",
            confidence: "medium",
            message: `Server "${server.name}" references home/system paths in its command or args.`,
            file: entry.path,
            line: server.line,
            snippet: toSafeSnippet(argText),
            remediation: "Confirm the filesystem access is required and scoped.",
          }),
        );
      }
    }
    return findings;
  },
};

// --- mcp.args-exec -------------------------------------------------------------

const EXEC_PATTERNS: RegExp[] = [
  /\b(curl|wget)\b[^\n|]*\|\s*(sh|bash|zsh)\b/i,
  /\b(sh|bash|zsh|cmd|powershell|pwsh)\b[^\n]*\s-c\b/i,
  /-enc(odedcommand)?\b/i,
  /\brm\s+-rf\b/i,
  /\b(iex|invoke-expression)\b/i,
];

const argsExecRule: Rule = {
  id: "mcp.args-exec",
  severity: "high",
  confidence: "medium",
  description: "Server command/args download or execute code.",
  kinds: [...MCP],
  check(entry): Finding[] {
    const findings: Finding[] = [];
    for (const server of servers(entry)) {
      const text = [server.command ?? "", ...server.args].join(" ");
      if (EXEC_PATTERNS.some((pattern) => pattern.test(text))) {
        findings.push(
          finding({
            ruleId: "mcp.args-exec",
            severity: "high",
            confidence: "medium",
            message: `Server "${server.name}" launches code via its command or args.`,
            file: entry.path,
            line: server.line,
            snippet: toSafeSnippet(redactSecrets(text)),
            remediation: "Review the command; pin and vendor the server where possible.",
          }),
        );
      }
    }
    return findings;
  },
};

// --- mcp.transport -------------------------------------------------------------

const LOOPBACK_RE = /^(localhost|127(\.\d+){3}|0\.0\.0\.0|\[?::1\]?)$/i;
const IP_LITERAL_RE = /^(\d{1,3}\.){3}\d{1,3}$/;

function hostOf(url: string): string | null {
  try {
    const parsed = new URL(url);
    return parsed.hostname;
  } catch {
    return null;
  }
}

const transportRule: Rule = {
  id: "mcp.transport",
  severity: "medium",
  confidence: "medium",
  description: "Remote MCP server uses plaintext HTTP or a loopback/IP-literal host.",
  kinds: [...MCP],
  check(entry): Finding[] {
    const findings: Finding[] = [];
    for (const server of servers(entry)) {
      if (!server.url) {
        continue;
      }
      const host = hostOf(server.url);
      if (server.url.toLowerCase().startsWith("http://")) {
        findings.push(
          finding({
            ruleId: "mcp.transport",
            severity: "medium",
            confidence: "high",
            message: `Server "${server.name}" uses plaintext HTTP.`,
            file: entry.path,
            line: server.line,
            snippet: toSafeSnippet(server.url),
            remediation: "Use HTTPS for remote MCP servers.",
          }),
        );
      }
      if (host && (LOOPBACK_RE.test(host) || IP_LITERAL_RE.test(host))) {
        findings.push(
          finding({
            ruleId: "mcp.transport",
            severity: "medium",
            confidence: "medium",
            message: `Server "${server.name}" points at a loopback/IP-literal host (${host}).`,
            file: entry.path,
            line: server.line,
            remediation: "Confirm the remote URL is the intended, trusted endpoint.",
          }),
        );
      }
    }
    return findings;
  },
};

// --- mcp.secrets ---------------------------------------------------------------

const PLACEHOLDER_RE =
  /(\$\{|\$[A-Z_]+\b|^<.*>$|your[-_ ]|changeme|placeholder|example|xxx|\.\.\.)/i;

function looksLikeRealSecret(value: string): boolean {
  if (value.length < 16 || PLACEHOLDER_RE.test(value)) {
    return false;
  }
  if (/\bsk-[A-Za-z0-9_-]{8,}\b|\bgh[pousr]_[A-Za-z0-9]{8,}\b|\bAKIA[0-9A-Z]{12,}\b/.test(value)) {
    return true;
  }
  // Long, mixed, high-variety string.
  const unique = new Set(value).size;
  return unique >= 10;
}

const secretsRule: Rule = {
  id: "mcp.secrets",
  severity: "high",
  confidence: "medium",
  description: "Hardcoded credential-looking values in env or headers.",
  kinds: [...MCP],
  check(entry): Finding[] {
    const findings: Finding[] = [];
    for (const server of servers(entry)) {
      for (const [scope, record] of [
        ["env", server.env],
        ["headers", server.headers],
      ] as const) {
        for (const [key, value] of Object.entries(record)) {
          if (looksLikeRealSecret(value)) {
            findings.push(
              finding({
                ruleId: "mcp.secrets",
                severity: "high",
                confidence: "medium",
                message: `Server "${server.name}" hardcodes a credential-looking value in ${scope} (${key}).`,
                file: entry.path,
                line: server.line,
                remediation:
                  "Move secrets out of the config; reference an env var or secret store.",
              }),
            );
          }
        }
      }
    }
    return findings;
  },
};

// --- mcp.hygiene ---------------------------------------------------------------

const RUNNER_RE = /^(npx|uvx|pnpm|bunx|yarn)$/i;

function unpinnedPackage(args: string[]): string | null {
  const pkgs = args.filter((arg) => !arg.startsWith("-"));
  for (const arg of pkgs) {
    // A version pin is an "@" after the first character (scoped names start with "@").
    if (arg.indexOf("@", 1) === -1) {
      return arg;
    }
  }
  return null;
}

const hygieneRule: Rule = {
  id: "mcp.hygiene",
  severity: "low",
  confidence: "medium",
  description: "Unpinned package runner (npx -y / uvx) fetches a floating version.",
  kinds: [...MCP],
  check(entry): Finding[] {
    const findings: Finding[] = [];
    for (const server of servers(entry)) {
      const command = (server.command ?? "").split(/[\\/]/).pop() ?? "";
      if (!RUNNER_RE.test(command)) {
        continue;
      }
      const pkg = unpinnedPackage(server.args);
      if (pkg) {
        findings.push(
          finding({
            ruleId: "mcp.hygiene",
            severity: "low",
            confidence: "medium",
            message: `Server "${server.name}" runs an unpinned package (${pkg}).`,
            file: entry.path,
            line: server.line,
            remediation: "Pin the package to a version or digest.",
          }),
        );
      }
    }
    return findings;
  },
};

export const mcpRules: Rule[] = [
  invalidRule,
  imperativeRule,
  shadowRule,
  overreachRule,
  argsExecRule,
  transportRule,
  secretsRule,
  hygieneRule,
];
