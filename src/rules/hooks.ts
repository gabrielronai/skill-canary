import { toSafeSnippet } from "../util/text.js";
import { DOWNLOAD_RUN_PATTERNS } from "./execution.js";
import type { FileEntry, Finding, Rule } from "./types.js";

const INSTALL_HOOKS = new Set(["preinstall", "install", "postinstall", "prepare"]);
const FETCH_RUN_RE =
  /\b(curl|wget|iwr|invoke-webrequest|node\s+-e|powershell|child_process|fetch\s*\()/i;

export const hookRule: Rule = {
  id: "hook.fetch-run",
  severity: "high",
  confidence: "medium",
  description: "Install/build hook downloads or executes code.",
  kinds: ["config"],
  check(entry: FileEntry): Finding[] {
    let data: unknown;
    try {
      data = JSON.parse(entry.content);
    } catch {
      return [];
    }
    const scripts = (data as { scripts?: unknown } | null)?.scripts;
    if (!scripts || typeof scripts !== "object") {
      return [];
    }

    const findings: Finding[] = [];
    for (const [name, value] of Object.entries(scripts as Record<string, unknown>)) {
      if (!INSTALL_HOOKS.has(name) || typeof value !== "string") {
        continue;
      }
      if (
        DOWNLOAD_RUN_PATTERNS.some((pattern) => pattern.test(value)) ||
        FETCH_RUN_RE.test(value)
      ) {
        const index = entry.lines.findIndex((line) => line.includes(name));
        findings.push({
          ruleId: "hook.fetch-run",
          severity: "high",
          confidence: "medium",
          message: `Install hook "${name}" downloads or executes code.`,
          file: entry.path,
          ...(index >= 0 ? { line: index + 1 } : {}),
          snippet: toSafeSnippet(value),
          remediation: "Review the hook; pin and vendor any fetched code.",
        });
      }
    }
    return findings;
  },
};
