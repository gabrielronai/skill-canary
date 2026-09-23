import { toSafeSnippet } from "../util/text.js";
import type { FileEntry, FileKind, Finding, Rule } from "./types.js";

const KINDS: FileKind[] = ["skill", "script", "config"];
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
  /(discord(?:app)?\.com\/api\/webhooks|webhook\.site|requestbin|pipedream\.net|ngrok(?:-free)?\.(?:io|app)|interact\.sh|oast\.(?:fun|pro|live|site|online|me)|burpcollaborator\.net|canarytokens\.(?:com|org)|hookbin\.com|beeceptor\.com)/i;

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

export const exfiltrationRules: Rule[] = [outboundRule, webhookRule];
