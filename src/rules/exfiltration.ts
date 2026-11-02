import { toSafeSnippet } from "../util/text.js";
import { sensitiveTarget } from "./secretAccess.js";
import type { FileEntry, FileKind, Finding, Rule } from "./types.js";

const KINDS: FileKind[] = ["skill", "script", "config", "agentconfig", "instructions"];
const URL_RE = /https?:\/\/[^\s"'<>)]+/i;

const SEND_PATTERNS: RegExp[] = [
  /\bcurl\b[^\n]*\b(-d|--data|--data-raw|-F|--form|--upload-file|-T)\b/i,
  /\bcurl\b[^\n]*\b(-X\s*POST|--request\s+POST)\b/i,
  /\bwget\b[^\n]*--post-(data|file)\b/i,
  /\b(requests\.(post|put|patch)|axios\.(post|put)|fetch)\s*\(/i,
  /\b(invoke-restmethod|invoke-webrequest|http\.request|net\.connect)\b/i,
  /\b(scp|rsync)\b[^\n]*@[^\s:]+:/i,
  /\b(post|upload|send|transmit|exfiltrate|leak)\b[\s\S]{0,60}https?:\/\//i,
];

const WEBHOOK_RE =
  /(discord(?:app)?\.com\/api\/webhooks|webhook\.site|requestbin|pipedream\.net|ngrok(?:-free)?\.(?:io|app)|interact\.sh|oast\.(?:fun|pro|live|site|online|me)|burpcollaborator\.net|canarytokens\.(?:com|org)|hookbin\.com|beeceptor\.com|glot\.io|pastebin\.com|paste\.ee|transfer\.sh|0x0\.st|file\.io|termbin\.com|dpaste\.(?:org|com)|hastebin\.com)/i;

const NETWORK_SINK_RE = /\b(?:curl|wget|nc|ncat|socat|scp|rsync)\b|>\s*\/dev\/(?:tcp|udp)\//i;

const SECRET_TO_NETWORK_KINDS: FileKind[] = ["skill", "script", "config", "instructions"];

export const secretToNetworkRule: Rule = {
  id: "exf.secret-to-network",
  severity: "critical",
  confidence: "high",
  description: "Reads credentials and sends them over the network in one step.",
  kinds: SECRET_TO_NETWORK_KINDS,
  check(entry: FileEntry): Finding[] {
    const findings: Finding[] = [];
    entry.lines.forEach((line, index) => {
      // A bearer token in an ordinary API call is not exfiltration.
      if (/\b(?:authorization|bearer)\b/i.test(line)) {
        return;
      }
      const target = sensitiveTarget(line);
      if (target && NETWORK_SINK_RE.test(line)) {
        findings.push({
          ruleId: "exf.secret-to-network",
          severity: "critical",
          confidence: "high",
          message: `Reads and sends ${target} over the network in one step.`,
          file: entry.path,
          line: index + 1,
          snippet: toSafeSnippet(line),
          remediation: "Remove the combined read-and-send; credentials must never leave the host.",
        });
      }
    });
    return findings;
  },
};

// --- exf.base-url-hijack -------------------------------------------------------

const BASE_URL_RE =
  /\b(ANTHROPIC_BASE_URL|OPENAI_BASE_URL|OPENAI_API_BASE|GEMINI_BASE_URL|GOOGLE_GENAI_BASE_URL|AZURE_OPENAI_ENDPOINT)\b\s*[:=]\s*["']?(https?:\/\/[^\s"']+)/i;

const OFFICIAL_HOSTS = new Set([
  "api.anthropic.com",
  "api.openai.com",
  "generativelanguage.googleapis.com",
]);

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "0.0.0.0", "[::1]", "host.docker.internal"]);

function isOfficialHost(host: string): boolean {
  const lower = host.toLowerCase();
  return OFFICIAL_HOSTS.has(lower) || lower.endsWith(".openai.azure.com");
}

export const baseUrlHijackRule: Rule = {
  id: "exf.base-url-hijack",
  severity: "high",
  confidence: "medium",
  description: "Points a model API base URL at a non-official host.",
  kinds: [...KINDS, "mcp"],
  check(entry: FileEntry): Finding[] {
    const findings: Finding[] = [];
    entry.lines.forEach((line, index) => {
      const match = BASE_URL_RE.exec(line);
      if (!match) {
        return;
      }
      const raw = match[2].replace(/[`'"<>\])}.,;]+$/, "");
      let host: string;
      try {
        host = new URL(raw).hostname;
      } catch {
        return;
      }
      if (isOfficialHost(host) || LOCAL_HOSTS.has(host.toLowerCase())) {
        return;
      }
      const risky = /^http:\/\//i.test(raw) || /^[\d.]+$|:/.test(host);
      findings.push({
        ruleId: "exf.base-url-hijack",
        severity: "high",
        confidence: risky ? "high" : "medium",
        message: `${match[1]} points at non-official host "${host}".`,
        file: entry.path,
        line: index + 1,
        snippet: toSafeSnippet(line),
        remediation:
          "Use the provider's official endpoint; a custom base URL can capture API keys.",
      });
    });
    return findings;
  },
};

export const outboundRule: Rule = {
  id: "exf.outbound",
  severity: "critical",
  confidence: "medium",
  description: "Sends local data to an external URL.",
  kinds: KINDS,
  check(entry: FileEntry): Finding[] {
    const urlMatch = entry.content.match(URL_RE);
    if (!urlMatch) {
      return [];
    }
    if (!SEND_PATTERNS.some((pattern) => pattern.test(entry.content))) {
      return [];
    }
    const index = entry.lines.findIndex((line) => line.includes(urlMatch[0]));
    return [
      {
        ruleId: "exf.outbound",
        severity: "critical",
        confidence: "medium",
        message: "Sends data to an external URL.",
        file: entry.path,
        ...(index >= 0 ? { line: index + 1 } : {}),
        snippet: toSafeSnippet(urlMatch[0]),
        remediation: "Confirm the destination is trusted and the data is meant to leave.",
      },
    ];
  },
};

export const webhookRule: Rule = {
  id: "exf.webhook",
  severity: "high",
  confidence: "high",
  description: "Known webhook or exfiltration endpoint.",
  kinds: KINDS,
  check(entry: FileEntry): Finding[] {
    const findings: Finding[] = [];
    entry.lines.forEach((line, index) => {
      if (WEBHOOK_RE.test(line)) {
        findings.push({
          ruleId: "exf.webhook",
          severity: "high",
          confidence: "high",
          message: "References a known webhook/exfiltration service.",
          file: entry.path,
          line: index + 1,
          snippet: toSafeSnippet(line),
          remediation: "Remove the endpoint unless it is deliberately used.",
        });
      }
    });
    return findings;
  },
};

export const exfiltrationRules: Rule[] = [
  outboundRule,
  webhookRule,
  secretToNetworkRule,
  baseUrlHijackRule,
];
