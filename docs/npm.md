# Publishing to npm

The package is publish-ready. The name is **`skillcanary`**; re-confirm it is
still available, or pick a scope, before the first real publish (a public npm
name must be globally unique).

## Pre-publish status (2026-09-15)

- Name **`skillcanary`** verified unclaimed on the public registry
  (`npm view skillcanary` → 404).
- `package.json`: name, version `0.4.0`, description, `license` (Apache-2.0),
  `bin`, `files`, `publishConfig.access=public`, `repository`, `homepage`, and
  `bugs` (github.com/gabrielronai/skill-canary) are set.
- `src/version.ts` `TOOL_VERSION` matches `package.json` (`0.4.0`).
- `npm pack --dry-run` file list verified: `dist/**`, `action.yml`, `LICENSE`,
  `README.md`, `package.json`, `skills/skillcanary/SKILL.md`.
- Not yet authenticated to npm on this machine (`npm login` required, 2FA).

## Before the first publish

1. `npm login` with an account that has 2FA enabled.
2. Confirm the version (`0.1.0` for the first alpha) and the `LICENSE`
   (Apache-2.0).

## Publish

```bash
npm login              # with 2FA enabled
npm run check          # typecheck + lint + tests
npm pack --dry-run     # inspect the file list (dist, action.yml, README, LICENSE)
npm publish --dry-run  # full publish without uploading (optional final check)
npm publish            # runs prepublishOnly (check + build) automatically
```

The name is unscoped, so no `--access` flag is needed; `publishConfig.access`
is already `public` for a future scoped name. `prepublishOnly` runs
`npm run check && npm run build`, so a broken build or failing test blocks the
publish.

## After publish

```bash
npx skillcanary scan . --format sarif --fail-on high
```

For a scoped name, `npx @scope/name scan .`.

## Versioning

- Pre-1.0, bump the minor for new rules or behaviour changes and the patch for
  fixes (`0.1.0` → `0.1.1` → `0.4.0`).
- Keep `src/version.ts` in sync with `package.json` `version`.
- Tag releases in git (`v0.1.0`) once the repo has a remote.
