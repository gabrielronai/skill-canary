import { toSafeSnippet } from "../util/text.js";
import type { FileEntry, Finding, Rule, Severity } from "./types.js";

const RULE_ID = "sec.env-read";

interface SensitiveTarget {
  re: RegExp;
  label: string;
}

const SENSITIVE_PATHS: SensitiveTarget[] = [
  { re: /(^|[^.\w])\.env(\b|\.)/i, label: "a .env file" },
  { re: /\.aws\/credentials\b/i, label: "AWS credentials" },
  { re: /\.ssh\/(?:id_|.*key)/i, label: "SSH keys" },
  { re: /\.netrc\b/i, label: ".netrc" },
  { re: /\.npmrc\b/i, label: ".npmrc" },
  { re: /\.config\/gcloud\b/i, label: "gcloud credentials" },
  { re: /\b(?:login\.keychain|cookies\.sqlite|login data)\b/i, label: "a browser/keychain store" },
];

const ENV_SECRET_RE =
  /\b(?:process\.env|os\.environ|getenv\(|env\[)[^\n]{0,80}(?:api[_-]?key|token|secret|password|credential|private[_-]?key)/i;

function firstMatch(line: string): { severity: Severity; message: string } | null {
  for (const target of SENSITIVE_PATHS) {
    if (target.re.test(line)) {
      return { severity: "high", message: `Reads ${target.label}, which may expose credentials.` };
    }
  }
  if (ENV_SECRET_RE.test(line)) {
    return { severity: "medium", message: "Reads a secret-looking environment variable." };
  }
  return null;
}

export const secretAccessRule: Rule = {
  id: RULE_ID,
  severity: "high",
  confidence: "medium",
  description: "Detects access to credential stores and secret-looking environment variables.",
  check(entry: FileEntry): Finding[] {
    const findings: Finding[] = [];
    entry.lines.forEach((line, index) => {
      const match = firstMatch(line);
      if (match) {
        findings.push({
          ruleId: RULE_ID,
          severity: match.severity,
          confidence: "medium",
          message: match.message,
          file: entry.path,
          line: index + 1,
          snippet: toSafeSnippet(line),
          remediation: "Confirm the skill genuinely needs this access; scope or remove it.",
        });
      }
    });
    return findings;
  },
};
