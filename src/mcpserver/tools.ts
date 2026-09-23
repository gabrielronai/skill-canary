import { fetchRemoteServer } from "../mcp/remote.js";
import { scanPackage } from "../packages/scan.js";
import { buildJsonReport } from "../report/json.js";
import { ALL_RULES } from "../rules/registry.js";
import type { FailThreshold, Finding } from "../rules/types.js";
import { meetsThreshold } from "../rules/types.js";
import { evaluate, remoteEntry, scan, scanMcpFile } from "../scan.js";

export interface ToolOutcome {
  text: string;
  isError: boolean;
}

const THRESHOLDS: FailThreshold[] = ["none", "critical", "high", "medium", "low", "info"];

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function splitRules(rules?: string): string[] | undefined {
  if (!rules) {
    return undefined;
  }
  return rules
    .split(",")
    .map((rule) => rule.trim())
    .filter(Boolean);
}

function report(findings: Finding[], failOn?: string): string {
  const threshold = THRESHOLDS.includes(failOn as FailThreshold)
    ? (failOn as FailThreshold)
    : "high";
  const payload = {
    ...buildJsonReport(findings),
    wouldFail: findings.some((finding) => meetsThreshold(finding.severity, threshold)),
  };
  return JSON.stringify(payload, null, 2);
}

export function listRulesTool(): ToolOutcome {
  const rules = ALL_RULES.map((rule) => ({
    id: rule.id,
    severity: rule.severity,
    confidence: rule.confidence,
    description: rule.description,
  }));
  return { text: JSON.stringify(rules, null, 2), isError: false };
}

export function explainRuleTool(id: string): ToolOutcome {
  const rule = ALL_RULES.find((candidate) => candidate.id === id);
  if (!rule) {
    return { text: `Unknown rule: ${id}`, isError: true };
  }
  return {
    text: JSON.stringify(
      {
        id: rule.id,
        severity: rule.severity,
        confidence: rule.confidence,
        description: rule.description,
      },
      null,
      2,
    ),
    isError: false,
  };
}

export function scanPathTool(args: {
  path: string;
  rules?: string;
  failOn?: string;
}): ToolOutcome {
  if (!args.path) {
    return { text: "Missing required argument: path", isError: true };
  }
  try {
    const findings = scan(args.path, { rules: splitRules(args.rules) });
    return { text: report(findings, args.failOn), isError: false };
  } catch (error) {
    return { text: `Scan failed: ${message(error)}`, isError: true };
  }
}

export function scanConfigTool(args: { file: string; rules?: string }): ToolOutcome {
  if (!args.file) {
    return { text: "Missing required argument: file", isError: true };
  }
  try {
    const findings = scanMcpFile(args.file, { rules: splitRules(args.rules) });
    return { text: report(findings), isError: false };
  } catch (error) {
    return { text: `Scan failed: ${message(error)}`, isError: true };
  }
}

export async function scanPackageTool(args: { spec: string }): Promise<ToolOutcome> {
  if (!args.spec) {
    return { text: "Missing required argument: spec", isError: true };
  }
  try {
    const findings = await scanPackage(args.spec);
    return { text: report(findings), isError: false };
  } catch (error) {
    return { text: `Package scan failed: ${message(error)}`, isError: true };
  }
}

export async function scanRemoteTool(args: {
  url: string;
  headers?: Record<string, string>;
  allowInsecure?: boolean;
}): Promise<ToolOutcome> {
  if (!args.url) {
    return { text: "Missing required argument: url", isError: true };
  }
  try {
    const server = await fetchRemoteServer(args.url, {
      headers: args.headers,
      allowInsecure: args.allowInsecure,
      allowPrivate: args.allowInsecure,
    });
    const findings = evaluate([remoteEntry(server)]);
    return { text: report(findings), isError: false };
  } catch (error) {
    return { text: `Remote scan failed: ${message(error)}`, isError: true };
  }
}
