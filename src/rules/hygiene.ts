import { toSafeSnippet } from "../util/text.js";
import type { FileEntry, Finding, Rule } from "./types.js";

const UNPINNED_RE = /\b(?:npx|uvx|bunx)\s+(?:-y|--yes)\s+([^\s]+)/i;
const HTTP_RE = /\bhttp:\/\/[^\s"'<>)]+/i;
const LOCAL_HOST_RE = /^http:\/\/(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)/i;

export const unpinnedRule: Rule = {
  id: "hygiene.unpinned",
  severity: "low",
  confidence: "medium",
  description: "Unpinned package runner (npx -y / uvx).",
  kinds: ["skill", "script"],
  check(entry: FileEntry): Finding[] {
    const findings: Finding[] = [];
    entry.lines.forEach((line, index) => {
      const match = UNPINNED_RE.exec(line);
      const pkg = match?.[1];
      if (pkg && pkg.indexOf("@", 1) === -1) {
        findings.push({
          ruleId: "hygiene.unpinned",
          severity: "low",
          confidence: "medium",
          message: `Runs an unpinned package (${pkg}).`,
          file: entry.path,
          line: index + 1,
          snippet: toSafeSnippet(line),
          remediation: "Pin the package to a version or digest.",
        });
      }
    });
    return findings;
  },
};

export const httpRule: Rule = {
  id: "hygiene.http",
  severity: "low",
  confidence: "low",
  description: "Plaintext HTTP URL (not localhost).",
  kinds: ["skill", "script", "config"],
  check(entry: FileEntry): Finding[] {
    const findings: Finding[] = [];
    entry.lines.forEach((line, index) => {
      const match = HTTP_RE.exec(line);
      if (match && !LOCAL_HOST_RE.test(match[0])) {
        findings.push({
          ruleId: "hygiene.http",
          severity: "low",
          confidence: "low",
          message: "Plaintext HTTP URL.",
          file: entry.path,
          line: index + 1,
          snippet: toSafeSnippet(match[0]),
          remediation: "Use HTTPS where possible.",
        });
      }
    });
    return findings;
  },
};

export const hygieneRules: Rule[] = [unpinnedRule, httpRule];
