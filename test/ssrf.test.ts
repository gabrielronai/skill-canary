import { describe, expect, it } from "vitest";
import { checkUrlSafety, isPrivateAddress } from "../src/net/ssrf.js";

describe("isPrivateAddress", () => {
  it("classifies private, loopback, link-local, and reserved ranges", () => {
    for (const address of [
      "127.0.0.1",
      "10.0.0.5",
      "192.168.1.1",
      "169.254.169.254",
      "172.16.0.1",
    ]) {
      expect(isPrivateAddress(address)).toBe(true);
    }
    expect(isPrivateAddress("::1")).toBe(true);
    expect(isPrivateAddress("fe80::1")).toBe(true);
  });

  it("allows public addresses", () => {
    expect(isPrivateAddress("8.8.8.8")).toBe(false);
    expect(isPrivateAddress("1.1.1.1")).toBe(false);
  });
});

describe("checkUrlSafety", () => {
  it("rejects non-http(s) schemes", async () => {
    expect((await checkUrlSafety("file:///etc/passwd")).ok).toBe(false);
  });

  it("rejects an invalid URL", async () => {
    expect((await checkUrlSafety("not a url")).ok).toBe(false);
  });

  it("rejects plaintext http unless insecure is allowed", async () => {
    const result = await checkUrlSafety("http://10.0.0.1/mcp");
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("HTTP");
  });

  it("blocks private addresses by literal IP (no DNS)", async () => {
    const result = await checkUrlSafety("https://10.0.0.1/mcp");
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("private");
  });

  it("blocks the cloud metadata address", async () => {
    expect((await checkUrlSafety("https://169.254.169.254/latest/meta-data/")).ok).toBe(false);
  });

  it("allows private addresses when explicitly permitted", async () => {
    expect((await checkUrlSafety("https://10.0.0.1/mcp", { allowPrivate: true })).ok).toBe(true);
  });
});
