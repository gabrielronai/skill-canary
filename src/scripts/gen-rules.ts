import { writeFileSync } from "node:fs";
import { ruleCatalog } from "../rules/catalog.js";

// Regenerate with `npm run gen:rules`; the registry test fails if this drifts.
const target = new URL("../../docs/rules.json", import.meta.url);
writeFileSync(target, `${JSON.stringify({ version: 1, rules: ruleCatalog() }, null, 2)}\n`);
