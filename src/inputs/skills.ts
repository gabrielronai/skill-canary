import { basename, dirname, extname } from "node:path";
import { parse as parseYaml } from "yaml";
import type { SkillMeta } from "../rules/types.js";

export const SKILL_FILENAME = "skill.md";

const SCRIPT_EXTS = new Set([
  ".sh",
  ".bash",
  ".zsh",
  ".ps1",
  ".py",
  ".js",
  ".mjs",
  ".cjs",
  ".ts",
  ".rb",
  ".pl",
  ".php",
]);

function toPosix(path: string): string {
  return path.split("\\").join("/");
}

/** True for any file named `SKILL.md` (case-insensitive). */
export function isSkillFile(relativePath: string): boolean {
  return basename(relativePath).toLowerCase() === SKILL_FILENAME;
}

export function isScriptFile(relativePath: string): boolean {
  return SCRIPT_EXTS.has(extname(relativePath).toLowerCase());
}

/** Directories that directly contain a `SKILL.md`, as posix relative paths. */
export function skillDirs(files: string[]): Set<string> {
  const dirs = new Set<string>();
  for (const file of files) {
    if (isSkillFile(file)) {
      dirs.add(toPosix(dirname(file)));
    }
  }
  return dirs;
}

export function isInsideSkillDir(relativePath: string, dirs: Set<string>): boolean {
  for (const dir of dirs) {
    // "." means a SKILL.md sits at the scan root, so its whole tree is the skill.
    if (dir === "." || relativePath.startsWith(`${dir}/`)) {
      return true;
    }
  }
  return false;
}

/** Parse `SKILL.md` YAML frontmatter (name, description, allowed-tools). */
export function parseSkillFrontmatter(content: string): SkillMeta {
  const match = /^---\s*\r?\n([\s\S]*?)\r?\n---/.exec(content);
  if (!match?.[1]) {
    return { allowedTools: [] };
  }
  try {
    const data = parseYaml(match[1]) as Record<string, unknown> | null;
    if (!data || typeof data !== "object") {
      return { allowedTools: [] };
    }
    const allowed = data["allowed-tools"];
    const allowedTools = Array.isArray(allowed)
      ? allowed.map(String)
      : typeof allowed === "string"
        ? allowed.split(/[,\s]+/).filter(Boolean)
        : [];
    const meta: SkillMeta = { allowedTools };
    if (typeof data.name === "string") {
      meta.name = data.name;
    }
    if (typeof data.description === "string") {
      meta.description = data.description;
    }
    return meta;
  } catch {
    return { allowedTools: [] };
  }
}
