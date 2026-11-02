import type { FileEntry, Finding } from "./types.js";

const DIRECTIVE_RE = /(?:#|\/\/|<!--|\/\*|--)\s*skillcanary:ignore\b([^\n]*)/i;
const ALL = "all";

/** Lines covered by an inline suppression; `all` suppresses every rule on them. */
function directives(entry: FileEntry): Map<number, Set<string> | typeof ALL> {
  const map = new Map<number, Set<string> | typeof ALL>();
  entry.lines.forEach((line, index) => {
    const match = DIRECTIVE_RE.exec(line);
    if (!match) {
      return;
    }
    const ids = (match[1] ?? "")
      .replace(/-->|\*\//g, "")
      .split(/[\s,]+/)
      .filter(Boolean);
    const value = ids.length === 0 ? ALL : new Set(ids);
    const start = index + 1;
    map.set(start, value);
    if (start + 1 <= entry.lines.length) {
      map.set(start + 1, value);
    }
  });
  return map;
}

/** Drop findings silenced by `# skillcanary:ignore <rule-id>` comments. */
export function applyInlineSuppressions(entry: FileEntry, findings: Finding[]): Finding[] {
  const map = directives(entry);
  if (map.size === 0) {
    return findings;
  }
  return findings.filter((finding) => {
    if (finding.line === undefined) {
      return true;
    }
    const rule = map.get(finding.line);
    return rule === undefined || (rule !== ALL && !rule.has(finding.ruleId));
  });
}
