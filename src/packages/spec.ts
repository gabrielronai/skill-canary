/** Parse package specs and extract them from MCP server commands. */

export interface PackageSpec {
  name: string;
  version?: string;
  raw: string;
}

const RUNNERS = new Set(["npx", "bunx", "pnpm", "yarn", "yarnpkg", "bun"]);

/** Parse `name`, `name@version`, or `@scope/name@version`. */
export function parsePackageSpec(raw: string): PackageSpec | null {
  const text = raw.trim();
  if (!text) {
    return null;
  }
  const at = text.indexOf("@", 1);
  if (at > 0) {
    const version = text.slice(at + 1);
    return {
      name: text.slice(0, at),
      ...(version ? { version } : {}),
      raw: text,
    };
  }
  return { name: text, raw: text };
}

/**
 * If an MCP server runs a package via a node package runner, return its spec.
 * Returns `null` for non-runners and for Python/other runners.
 */
export function packageSpecFromServer(server: {
  command?: string;
  args: string[];
}): string | null {
  const command = (server.command ?? "").split(/[\\/]/).pop()?.toLowerCase() ?? "";
  if (!RUNNERS.has(command)) {
    return null;
  }

  let tokens = server.args.filter((arg) => !arg.startsWith("-"));
  if (command === "pnpm" || command === "yarn" || command === "yarnpkg") {
    const index = tokens.findIndex((token) => token === "dlx" || token === "exec");
    if (index === -1) {
      return null;
    }
    tokens = tokens.slice(index + 1);
  }

  const spec = tokens[0];
  return spec && parsePackageSpec(spec) ? spec : null;
}
