import { toSafeSnippet } from "../util/text.js";
import type { Confidence, FileEntry, FileKind, Finding, Rule, Severity } from "./types.js";

const KINDS: FileKind[] = ["skill", "script", "config"];

/** `curl … | sh` and friends. Exported for the install-hook rule. */
export const DOWNLOAD_RUN_PATTERNS: RegExp[] = [
  /\b(curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(sh|bash|zsh|python3?|node|perl)\b/i,
  /\b(iwr|invoke-webrequest|curl|wget)\b[^\n]*\|\s*(iex|invoke-expression)\b/i,
  /\b(source|\.)\s*<\(\s*curl\b/i,
  /\bbash\s+<\(\s*curl\b/i,
];

const DESTRUCTIVE_PATTERNS: RegExp[] = [
  /\brm\s+-[a-z]*r[a-z]*f\b/i,
  /\brm\s+-[a-z]*f[a-z]*r\b/i,
  /\bmkfs(?:\.\w+)?\b/i,
  /\bdd\s+if=/i,
  /:\(\)\s*\{/,
  /\bchmod\s+-R\s+777\b/i,
  /\bshred\b/i,
  />\s*\/dev\/sd[a-z]/i,
];

const DYNAMIC_PATTERNS: RegExp[] = [
  /\beval\s*\(/,
  /\bexec\s*\(/,
  /new\s+Function\s*\(/,
  /\bchild_process\b/,
  /\bos\.system\s*\(/,
  /\bsubprocess\.[A-Za-z_]+\([^)\n]*shell\s*=\s*True/i,
  /\bRuntime\.getRuntime\(\)\.exec\b/,
  /\bpopen\s*\(/,
];

function matchLines(
  entry: FileEntry,
  patterns: RegExp[],
  ruleId: string,
  severity: Severity,
  confidence: Confidence,
  message: string,
  remediation: string,
): Finding[] {
  const findings: Finding[] = [];
  entry.lines.forEach((line, index) => {
    if (patterns.some((pattern) => pattern.test(line))) {
      findings.push({
        ruleId,
        severity,
        confidence,
        message,
        file: entry.path,
        line: index + 1,
        snippet: toSafeSnippet(line),
        remediation,
      });
    }
  });
  return findings;
}

export const destructiveRule: Rule = {
  id: "exec.destructive",
  severity: "high",
  confidence: "medium",
  description: "Destructive command (broad delete, wipe, or disk write).",
  kinds: KINDS,
  check: (entry) =>
    matchLines(
      entry,
      DESTRUCTIVE_PATTERNS,
      "exec.destructive",
      "high",
      "medium",
      "Destructive command (broad delete or disk write).",
      "Scope the command; confirm it cannot delete user data.",
    ),
};

export const downloadRunRule: Rule = {
  id: "exec.download-run",
  severity: "critical",
  confidence: "high",
  description: "Downloads and executes a remote script.",
  kinds: KINDS,
  check: (entry) =>
    matchLines(
      entry,
      DOWNLOAD_RUN_PATTERNS,
      "exec.download-run",
      "critical",
      "high",
      "Downloads and executes remote code.",
      "Vendor and pin the script, or remove the download-and-run.",
    ),
};

export const dynamicExecRule: Rule = {
  id: "exec.dynamic",
  severity: "medium",
  confidence: "low",
  description: "Dynamic code execution (eval/exec/shell).",
  kinds: KINDS,
  check: (entry) =>
    matchLines(
      entry,
      DYNAMIC_PATTERNS,
      "exec.dynamic",
      "medium",
      "low",
      "Dynamic code execution on potentially untrusted input.",
      "Avoid eval/exec and shell invocation on untrusted input.",
    ),
};
