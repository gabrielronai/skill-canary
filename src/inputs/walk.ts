import { readFileSync, readdirSync, statSync } from "node:fs";
import type { Dirent } from "node:fs";
import { extname, join, relative, sep } from "node:path";

const IGNORE_DIRS = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  "out",
  "coverage",
  "vendor",
  ".next",
  ".turbo",
  ".venv",
  "venv",
  "__pycache__",
  ".mypy_cache",
  ".pytest_cache",
  ".ruff_cache",
]);

const BINARY_EXTS = new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".ico",
  ".pdf",
  ".zip",
  ".gz",
  ".tar",
  ".tgz",
  ".7z",
  ".rar",
  ".woff",
  ".woff2",
  ".ttf",
  ".otf",
  ".eot",
  ".mp3",
  ".mp4",
  ".mov",
  ".avi",
  ".so",
  ".dll",
  ".dylib",
  ".exe",
  ".bin",
  ".class",
  ".jar",
  ".wasm",
]);

const MAX_FILE_BYTES = 1_000_000;

function toPosix(path: string): string {
  return path.split(sep).join("/");
}

function readEntries(dir: string): Dirent<string>[] {
  try {
    return readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
}

/** True when `rel` is, or is inside, one of the excluded paths. */
export function isExcluded(rel: string, excludes: string[]): boolean {
  return excludes.some((entry) => {
    const clean = entry.replace(/\/+$/, "");
    if (clean.length === 0) {
      return false;
    }
    return rel === clean || rel.startsWith(`${clean}/`);
  });
}

function shouldSkipFile(fullPath: string): boolean {
  if (BINARY_EXTS.has(extname(fullPath).toLowerCase())) {
    return true;
  }
  try {
    return statSync(fullPath).size > MAX_FILE_BYTES;
  } catch {
    return true;
  }
}

/** Recursively list text files under `root` (relative, forward-slash paths). */
export function walkFiles(root: string, excludes: string[] = []): string[] {
  const results: string[] = [];

  const visit = (dir: string, relDir: string): void => {
    const entries = readEntries(dir);
    for (const entry of entries) {
      const rel = relDir ? `${relDir}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        if (IGNORE_DIRS.has(entry.name) || isExcluded(rel, excludes)) {
          continue;
        }
        visit(join(dir, entry.name), rel);
      } else if (entry.isFile()) {
        if (isExcluded(rel, excludes) || shouldSkipFile(join(dir, entry.name))) {
          continue;
        }
        results.push(rel);
      }
    }
  };

  visit(root, "");
  results.sort();
  return results;
}

export function readText(root: string, relativePath: string): string {
  return readFileSync(join(root, relativePath), "utf8");
}
