import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

const PRIVATE_V4: RegExp[] = [
  /^0\./,
  /^10\./,
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,
  /^127\./,
  /^169\.254\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.0\.0\./,
  /^192\.168\./,
  /^198\.(1[89])\./,
  /^22[4-9]\./,
  /^2[3-5]\d\./,
];

export function isPrivateIpv4(address: string): boolean {
  return PRIVATE_V4.some((pattern) => pattern.test(address));
}

export function isPrivateIpv6(address: string): boolean {
  const lower = address.toLowerCase();
  if (lower === "::1" || lower === "::") {
    return true;
  }
  if (lower.startsWith("fc") || lower.startsWith("fd") || lower.startsWith("fe80")) {
    return true;
  }
  if (lower.startsWith("::ffff:")) {
    return isPrivateIpv4(lower.slice("::ffff:".length));
  }
  return false;
}

export function isPrivateAddress(address: string): boolean {
  const version = isIP(address);
  if (version === 4) {
    return isPrivateIpv4(address);
  }
  if (version === 6) {
    return isPrivateIpv6(address);
  }
  return false;
}

export interface UrlSafetyOptions {
  allowInsecure?: boolean;
  allowPrivate?: boolean;
}

export interface UrlSafetyResult {
  ok: boolean;
  reason?: string;
  addresses?: string[];
}

/**
 * Guard against SSRF before making a request. Rejects non-http(s) schemes,
 * plaintext HTTP (unless allowed), and any host resolving to a private,
 * loopback, link-local, or reserved address (unless allowed).
 */
export async function checkUrlSafety(
  rawUrl: string,
  options: UrlSafetyOptions = {},
): Promise<UrlSafetyResult> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return { ok: false, reason: "invalid URL" };
  }

  if (url.protocol !== "https:" && url.protocol !== "http:") {
    return { ok: false, reason: `unsupported scheme ${url.protocol}` };
  }
  if (url.protocol === "http:" && !options.allowInsecure) {
    return { ok: false, reason: "plaintext HTTP is not allowed (use --allow-insecure)" };
  }
  if (options.allowPrivate) {
    return { ok: true };
  }

  const host = url.hostname;
  let addresses: string[];
  if (isIP(host)) {
    addresses = [host];
  } else {
    try {
      const results = await lookup(host, { all: true });
      addresses = results.map((result) => result.address);
    } catch (error) {
      return {
        ok: false,
        reason: `DNS lookup failed: ${error instanceof Error ? error.message : error}`,
      };
    }
  }

  for (const address of addresses) {
    if (isPrivateAddress(address)) {
      return { ok: false, reason: `blocked private address ${address}`, addresses };
    }
  }
  return { ok: true, addresses };
}
