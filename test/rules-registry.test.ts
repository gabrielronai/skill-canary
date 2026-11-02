import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { ruleCatalog } from "../src/rules/catalog.js";

const docs = {
  registry: JSON.parse(readFileSync("docs/rules.json", "utf8")),
  reference: readFileSync("docs/scanning-rules.md", "utf8"),
  usage: readFileSync("docs/usage.md", "utf8"),
  site: readFileSync("site/index.html", "utf8"),
};

describe("rule registry", () => {
  it("keeps docs/rules.json in sync with the code", () => {
    expect(docs.registry).toEqual({ version: 1, rules: ruleCatalog() });
  });

  it("documents every rule in the reference, usage guide, and site", () => {
    for (const rule of ruleCatalog()) {
      expect(docs.reference).toContain(`\`${rule.id}\``);
      expect(docs.usage).toContain(`\`${rule.id}\``);
      expect(docs.site).toContain(`<code>${rule.id}</code>`);
    }
  });
});
