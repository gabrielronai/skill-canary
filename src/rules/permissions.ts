import type { FileEntry, Finding, Rule } from "./types.js";

const BROAD_TOOLS =
  /^(bash|shell|write|edit|notebookedit|webfetch|websearch|computer|execute|run|network|http|\*)$/i;

export const skillPermissionsRule: Rule = {
  id: "skill.permissions",
  severity: "medium",
  confidence: "low",
  description: "Skill declares broad tool permissions.",
  kinds: ["skill"],
  check(entry: FileEntry): Finding[] {
    const tools = entry.skill?.allowedTools ?? [];
    const broad = tools.filter((tool) => BROAD_TOOLS.test(tool.trim()) || tool.includes("*"));
    if (broad.length === 0) {
      return [];
    }
    return [
      {
        ruleId: "skill.permissions",
        severity: "medium",
        confidence: "low",
        message: `Skill declares broad tool access (${broad.join(", ")}).`,
        file: entry.path,
        remediation: "Scope allowed-tools to what the skill actually needs.",
      },
    ];
  },
};
