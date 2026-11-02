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
  { re: /\.kube\/config\b/i, label: "kubeconfig" },
  { re: /\.docker\/config\.json\b/i, label: "Docker credentials" },
  { re: /\b\.(?:bash|zsh)_history\b/i, label: "shell history" },
  { re: /\/etc\/shadow\b/i, label: "/etc/shadow" },
  { re: /\/etc\/passwd\b/i, label: "/etc/passwd" },
  { re: /\b(?:login\.keychain|cookies\.sqlite|login data)\b/i, label: "a browser/keychain store" },
];

const ENV_SECRET_RE =
  /\b(?:process\.env|os\.environ|getenv\(|env\[)[^\n]{0,80}(?:api[_-]?key|token|secret|password|credential|private[_-]?key)/i;

// Commands that dump the whole environment, as opposed to reading one variable.
const ENV_DUMP_RE = /(?:^|[|;&]\s*|\bsudo\s+)(?:printenv|env|set)\b\s*(?:\||>|$)/i;

// Reading a secret-looking variable for display or piping.
const ENV_VALUE_RE =
  /\b(?:cat|less|more|head|tail|echo|printf|print)\b[^\n]{0,40}(?:\$\{?[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|PASSWD)[A-Z0-9_]*\}?|\/proc\/self\/environ)/i;

/** Label of the sensitive target referenced on this line, if any. */
export function sensitiveTarget(line: string): string | null {
  for (const target of SENSITIVE_PATHS) {
    if (target.re.test(line)) {
      return target.label;
    }
  }
  if (ENV_DUMP_RE.test(line)) {
    return "environment variables";
  }
  if (ENV_VALUE_RE.test(line) || ENV_SECRET_RE.test(line)) {
    return "a secret environment variable";
  }
  return null;
}

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

// --- sec.hardcoded-secret ------------------------------------------------------

const HARDCODED_SECRETS: SensitiveTarget[] = [
  { re: /\bsk-[A-Za-z0-9_-]{16,}\b/, label: "an API key" },
  { re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/, label: "a GitHub token" },
  { re: /\bAKIA[0-9A-Z]{16}\b/, label: "an AWS access key" },
  { re: /\bAIza[0-9A-Za-z_-]{30,}\b/, label: "a Google API key" },
  { re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, label: "a Slack token" },
  { re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/, label: "a private key" },
];

const PLACEHOLDER_RE = /(?:example|placeholder|your[-_ ]|xxxx|redacted|dummy|fake)/i;

export const hardcodedSecretRule: Rule = {
  id: "sec.hardcoded-secret",
  severity: "high",
  confidence: "medium",
  description: "Detects credentials committed in skill or config content.",
  kinds: ["skill", "script", "config", "instructions", "agentconfig"],
  check(entry: FileEntry): Finding[] {
    const findings: Finding[] = [];
    entry.lines.forEach((line, index) => {
      if (PLACEHOLDER_RE.test(line)) {
        return;
      }
      for (const target of HARDCODED_SECRETS) {
        if (target.re.test(line)) {
          findings.push({
            ruleId: "sec.hardcoded-secret",
            severity: "high",
            confidence: "medium",
            message: `Contains ${target.label} in source.`,
            file: entry.path,
            line: index + 1,
            snippet: toSafeSnippet(line),
            remediation: "Remove the credential, rotate it, and load it from a secret store.",
          });
          break;
        }
      }
    });
    return findings;
  },
};
