import { mkdir, mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { x as extractTar } from "tar";
import type { PackageSpec } from "./spec.js";

export interface ResolvedPackage {
  spec: PackageSpec;
  /** Directory to scan. */
  dir: string;
  source: "npm" | "local";
  cleanup: () => Promise<void>;
}

export interface ResolveOptions {
  maxBytes?: number;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
  registry?: string;
}

const DEFAULT_MAX_BYTES = 10 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 20_000;
const DEFAULT_REGISTRY = "https://registry.npmjs.org";

/** Resolve a local directory as a package (no network). */
export async function resolveLocalPackage(dir: string): Promise<ResolvedPackage | null> {
  try {
    const info = await stat(dir);
    if (!info.isDirectory()) {
      return null;
    }
  } catch {
    return null;
  }
  return { spec: { name: dir, raw: dir }, dir, source: "local", cleanup: async () => {} };
}

async function fetchWithTimeout(
  doFetch: typeof fetch,
  url: string,
  timeoutMs: number,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await doFetch(url, { signal: controller.signal, redirect: "follow" });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Resolve an npm package to a directory by downloading its tarball and
 * extracting it to a temp dir. The extracted files are never executed; the
 * caller scans and then cleans up.
 */
export async function resolveNpmPackage(
  spec: PackageSpec,
  options: ResolveOptions = {},
): Promise<ResolvedPackage> {
  if (!spec.name) {
    throw new Error("empty package name");
  }
  const doFetch = options.fetchImpl ?? fetch;
  const registry = (options.registry ?? DEFAULT_REGISTRY).replace(/\/+$/, "");
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;

  const encodedName = spec.name.replace(/\//g, "%2f");
  const metaResponse = await fetchWithTimeout(doFetch, `${registry}/${encodedName}`, timeoutMs);
  if (!metaResponse.ok) {
    throw new Error(`registry returned HTTP ${metaResponse.status} for ${spec.name}`);
  }
  const meta = (await metaResponse.json()) as {
    "dist-tags"?: Record<string, string>;
    versions?: Record<string, { dist?: { tarball?: string } }>;
  };
  const version = spec.version ?? meta["dist-tags"]?.latest;
  const versionData = version ? meta.versions?.[version] : undefined;
  const tarball = versionData?.dist?.tarball;
  if (!version || !tarball) {
    throw new Error(`version ${spec.version ?? "latest"} not found for ${spec.name}`);
  }

  const tarResponse = await fetchWithTimeout(doFetch, tarball, timeoutMs);
  if (!tarResponse.ok) {
    throw new Error(`tarball download returned HTTP ${tarResponse.status}`);
  }
  const buffer = Buffer.from(await tarResponse.arrayBuffer());
  if (buffer.byteLength > maxBytes) {
    throw new Error(`package exceeds the ${Math.round(maxBytes / 1024 / 1024)} MB limit`);
  }

  const tmp = await mkdtemp(join(tmpdir(), "skillcanary-pkg-"));
  try {
    const tgzPath = join(tmp, "package.tgz");
    await writeFile(tgzPath, buffer);
    const outDir = join(tmp, "package");
    await mkdir(outDir);
    await extractTar({ file: tgzPath, cwd: outDir, strip: 1 });
    return {
      spec: {
        name: spec.name,
        ...(spec.version ? { version: spec.version } : { version }),
        raw: spec.raw,
      },
      dir: outDir,
      source: "npm",
      cleanup: async () => {
        await rm(tmp, { recursive: true, force: true });
      },
    };
  } catch (error) {
    await rm(tmp, { recursive: true, force: true });
    throw error;
  }
}
