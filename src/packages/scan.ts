import type { Finding } from "../rules/types.js";
import { scan } from "../scan.js";
import { resolveLocalPackage, resolveNpmPackage } from "./resolver.js";
import type { ResolveOptions } from "./resolver.js";
import { parsePackageSpec } from "./spec.js";
import type { PackageSpec } from "./spec.js";

export interface ScanPackageOptions extends ResolveOptions {
  rules?: string[];
}

/**
 * Scan a package: a local directory if the spec is a path, otherwise an npm
 * package resolved from the registry. Files are never executed.
 */
export async function scanPackage(
  specText: string,
  options: ScanPackageOptions = {},
): Promise<Finding[]> {
  const local = await resolveLocalPackage(specText);
  const fallbackSpec: PackageSpec = parsePackageSpec(specText) ?? { name: specText, raw: specText };
  const resolved = local ?? (await resolveNpmPackage(fallbackSpec, options));

  try {
    const prefix =
      resolved.source === "npm"
        ? `npm://${resolved.spec.name}@${resolved.spec.version ?? "latest"}`
        : `local://${resolved.spec.name}`;
    return scan(resolved.dir, { rules: options.rules }).map((finding) => ({
      ...finding,
      file: `${prefix}/${finding.file}`,
    }));
  } finally {
    await resolved.cleanup();
  }
}
