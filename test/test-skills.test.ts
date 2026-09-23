import { readdirSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { scan } from "../src/scan.js";

function ruleIds(relativePath: string): Set<string> {
  return new Set(scan(`test-skills/${relativePath}`).map((finding) => finding.ruleId));
}

const M0_RULES = ["inj.ignore-previous", "obf.zero-width", "sec.env-read"];

const safeDirs = readdirSync("test-skills", { withFileTypes: true })
  .filter((entry) => entry.isDirectory() && entry.name.startsWith("safe-"))
  .map((entry) => entry.name)
  .sort();

describe("malicious skill fixtures (M0 detections)", () => {
  it("flags instruction-override skills with inj.ignore-previous", () => {
    for (const name of [
      "prompt-injection-ignore-previous",
      "hide-actions-from-user",
      "act-without-confirmation",
    ]) {
      expect(ruleIds(name).has("inj.ignore-previous")).toBe(true);
    }
  });

  it("flags hidden zero-width characters with obf.zero-width", () => {
    expect(ruleIds("hidden-zero-width-instructions").has("obf.zero-width")).toBe(true);
  });

  it("flags credential access with sec.env-read", () => {
    expect(ruleIds("read-env-secrets").has("sec.env-read")).toBe(true);
    expect(ruleIds("read-cloud-credentials").has("sec.env-read")).toBe(true);
  });

  it("does not fire M0 rules on the MCP description-injection fixture", () => {
    const found = [...ruleIds("mcp-tool-description-injection")];
    expect(found.some((id) => M0_RULES.includes(id))).toBe(false);
  });

  it("flags MCP description injection with mcp.imperative-desc", () => {
    expect(ruleIds("mcp-tool-description-injection").has("mcp.imperative-desc")).toBe(true);
  });

  it("flags the MCP-specific malicious fixtures", () => {
    expect(ruleIds("mcp-tool-shadowing").has("mcp.shadow")).toBe(true);
    expect(ruleIds("mcp-env-secrets").has("mcp.secrets")).toBe(true);
    expect(ruleIds("mcp-args-download-and-run").has("mcp.args-exec")).toBe(true);
    expect(ruleIds("mcp-remote-http").has("mcp.transport")).toBe(true);
    expect(ruleIds("mcp-unpinned-npx").has("mcp.hygiene")).toBe(true);
    expect(ruleIds("mcp-path-overreach").has("mcp.overreach")).toBe(true);
  });

  it("flags the remaining generic M1 fixtures", () => {
    expect(ruleIds("exfiltrate-data-to-webhook").has("exf.outbound")).toBe(true);
    expect(ruleIds("download-and-run-remote-script").has("exec.download-run")).toBe(true);
    expect(ruleIds("destructive-cleanup").has("exec.destructive")).toBe(true);
    expect(ruleIds("base64-encoded-payload").has("obf.encoded-blob")).toBe(true);
    expect(ruleIds("postinstall-hook-download").has("hook.fetch-run")).toBe(true);
    expect(ruleIds("excessive-permissions").has("skill.permissions")).toBe(true);
    expect(ruleIds("hidden-html-comment").has("inj.hidden-instruction")).toBe(true);
  });
});

describe("safe skill fixtures (no false positives)", () => {
  it("has at least one safe fixture", () => {
    expect(safeDirs.length).toBeGreaterThan(0);
  });

  it.each(safeDirs)("reports nothing for %s", (name) => {
    expect(scan(`test-skills/${name}`)).toHaveLength(0);
  });
});
