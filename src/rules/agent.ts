import { toSafeSnippet } from "../util/text.js";
import { DOWNLOAD_RUN_PATTERNS } from "./execution.js";
import type { FileEntry, Finding, Rule } from "./types.js";

const KINDS = ["agentconfig"] as const;

interface AgentHook {
  event: string;
  command: string;
}

const DANGEROUS_COMMAND: RegExp[] = [
  ...DOWNLOAD_RUN_PATTERNS,
  /\/dev\/(?:tcp|udp)\//i,
  /\b(?:nc|ncat)\b[^\n]*\s-e\s/i,
  /\bsocat\b[^\n]*\bexec:/i,
  /\b(?:base64|eval|exec)\b/i,
  /\b(?:curl|wget|invoke-webrequest|irm)\b/i,
  /\b(?:\.ssh|\.aws|\.env|credentials|id_rsa)\b/i,
];

function asRecord(value: unknown): Record<string, unknown> | null {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return null;
}

function parseConfig(entry: FileEntry): Record<string, unknown> | null {
  try {
    return asRecord(JSON.parse(entry.content));
  } catch {
    return null;
  }
}

function lineOf(entry: FileEntry, needle: string): number | undefined {
  const index = entry.lines.findIndex(
    (line) => line.includes(needle) || line.includes(`"${needle}"`),
  );
  return index >= 0 ? index + 1 : undefined;
}

function collectHooks(root: Record<string, unknown>): AgentHook[] {
  const hooks = asRecord(root.hooks);
  if (!hooks) {
    return [];
  }
  const collected: AgentHook[] = [];
  for (const [event, value] of Object.entries(hooks)) {
    if (!Array.isArray(value)) {
      continue;
    }
    for (const item of value) {
      const record = asRecord(item);
      if (!record) {
        continue;
      }
      const inner = Array.isArray(record.hooks) ? record.hooks : [record];
      for (const hook of inner) {
        const command = asRecord(hook)?.command;
        if (typeof command === "string" && command.trim()) {
          collected.push({ event, command });
        }
      }
    }
  }
  return collected;
}

export const hookExecRule: Rule = {
  id: "agent.hook-exec",
  severity: "high",
  confidence: "medium",
  description: "Agent config registers a command hook that runs automatically.",
  kinds: [...KINDS],
  check(entry: FileEntry): Finding[] {
    const root = parseConfig(entry);
    if (!root) {
      return [];
    }
    return collectHooks(root).map((hook) => {
      const dangerous = DANGEROUS_COMMAND.some((pattern) => pattern.test(hook.command));
      return {
        ruleId: "agent.hook-exec",
        severity: dangerous ? ("critical" as const) : ("high" as const),
        confidence: "high" as const,
        message: `"${hook.event}" hook runs a command automatically.`,
        file: entry.path,
        line: lineOf(entry, hook.command),
        snippet: toSafeSnippet(hook.command),
        remediation: "Remove the hook or confirm the command is trusted and necessary.",
      };
    });
  },
};

const WILDCARD_ALLOW_RE = /^(?:\*|(?:Bash|Write|Edit|Read|WebFetch|Task)\(\*\))$/i;

export const unsafeSettingRule: Rule = {
  id: "agent.unsafe-setting",
  severity: "high",
  confidence: "medium",
  description: "Agent config weakens sandboxing, approvals, or MCP consent.",
  kinds: [...KINDS],
  check(entry: FileEntry): Finding[] {
    const root = parseConfig(entry);
    if (!root) {
      return [];
    }
    const findings: Finding[] = [];
    const push = (message: string, key: string, remediation: string) => {
      findings.push({
        ruleId: "agent.unsafe-setting",
        severity: "high",
        confidence: "medium",
        message,
        file: entry.path,
        line: lineOf(entry, key),
        remediation,
      });
    };

    if (root.dangerouslyDisableSandbox === true) {
      push(
        "Sandbox execution is disabled.",
        "dangerouslyDisableSandbox",
        "Keep the sandbox enabled; remove the override.",
      );
    }

    const permissions = asRecord(root.permissions);
    if (permissions?.defaultMode === "bypassPermissions") {
      push(
        "Permission mode bypasses all approval prompts.",
        "defaultMode",
        "Use a mode that still prompts before sensitive actions.",
      );
    }
    if (Array.isArray(permissions?.allow)) {
      const wildcard = permissions.allow.find(
        (item) => typeof item === "string" && WILDCARD_ALLOW_RE.test(item),
      );
      if (typeof wildcard === "string") {
        push(
          `Permissions pre-approve a wildcard tool scope ("${wildcard}").`,
          wildcard,
          "Pre-approve only the specific commands the project needs.",
        );
      }
    }

    if (typeof root.apiKeyHelper === "string" && root.apiKeyHelper.trim()) {
      push(
        "A custom apiKeyHelper command runs to supply credentials.",
        "apiKeyHelper",
        "Remove the helper and provide credentials through the normal login flow.",
      );
    }
    if (root.enableAllProjectMcpServers === true) {
      push(
        "All project MCP servers are auto-approved.",
        "enableAllProjectMcpServers",
        "Require explicit approval for each MCP server.",
      );
    }
    if (Array.isArray(root.enabledMcpjsonServers) && root.enabledMcpjsonServers.length > 0) {
      push(
        "Project MCP servers are pre-approved by name.",
        "enabledMcpjsonServers",
        "Review the named servers before allowing automatic approval.",
      );
    }

    return findings;
  },
};

export const agentRules: Rule[] = [hookExecRule, unsafeSettingRule];
