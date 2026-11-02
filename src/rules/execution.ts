import { toSafeSnippet } from "../util/text.js";
import type { Confidence, FileEntry, FileKind, Finding, Rule, Severity } from "./types.js";

const KINDS: FileKind[] = ["skill", "script", "config", "agentconfig", "instructions"];

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

const REVERSE_SHELL_PATTERNS: RegExp[] = [
  /\/dev\/(?:tcp|udp)\//i,
  /\b(?:nc|ncat)\b[^\n]*\s-e\s/i,
  /\bsocat\b[^\n]*\bexec:/i,
  /\bbash\s+-i\b[^\n]*(?:>&|0>&1|\/dev\/tcp)/i,
  /\bmkfifo\b[^\n]*\b(?:nc|ncat)\b/i,
  /\bNew-Object\s+(?:System\.)?Net\.Sockets\.TCPClient\b/i,
];

const SECURITY_DISABLE_PATTERNS: RegExp[] = [
  /\bxattr\s+-[a-z]*d\s+com\.apple\.quarantine\b/i,
  /\bspctl\s+--master-disable\b/i,
  /\bcsrutil\s+disable\b/i,
  /\b(?:Set|Add)-MpPreference\b[^\n]*(?:DisableRealtimeMonitoring|ExclusionPath|ExclusionProcess|DisableIOAVProtection|DisableScriptScanning|DisableAntiSpyware)\b/i,
  /\b(?:ufw\s+disable|setenforce\s+0|iptables\s+-F)\b/i,
  /\bdefaults\s+write\b[^\n]*(?:LSQuarantine|com\.apple\.quarantine)\b/i,
  /\bDisableAntiSpyware\b/i,
  /\b(?:disable|bypass|turn\s+off)\b[^\n]{0,40}\b(?:antivirus|anti-virus|defender|smartscreen|firewall|gatekeeper|quarantine)\b/i,
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

export const reverseShellRule: Rule = {
  id: "exec.reverse-shell",
  severity: "critical",
  confidence: "high",
  description: "Reverse or bind shell construction.",
  kinds: KINDS,
  check: (entry) =>
    matchLines(
      entry,
      REVERSE_SHELL_PATTERNS,
      "exec.reverse-shell",
      "critical",
      "high",
      "Builds a reverse or bind shell.",
      "Remove shell access; if the skill needs one, vendor and review it.",
    ),
};

export const securityDisableRule: Rule = {
  id: "exec.security-disable",
  severity: "high",
  confidence: "medium",
  description: "Disables an OS security control.",
  kinds: KINDS,
  check: (entry) =>
    matchLines(
      entry,
      SECURITY_DISABLE_PATTERNS,
      "exec.security-disable",
      "high",
      "medium",
      "Disables an operating-system security control.",
      "Do not weaken antivirus, firewall, quarantine, or sandbox protections.",
    ),
};
