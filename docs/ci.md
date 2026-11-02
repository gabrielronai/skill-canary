# CI integration

`SkillCanary` runs in CI and fails the build at a severity you choose. It also
emits SARIF, so findings appear in GitHub's code-scanning UI.

## GitHub Actions

```yaml
name: scan
on: [push, pull_request]

permissions:
  contents: read
  security-events: write # required to upload SARIF

jobs:
  skillcanary:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: gabrielronai/skill-canary@v0   # marketplace ref once published
        with:
          path: .
          fail-on: high
          upload-sarif: "true"
```

Until the action is listed on the Marketplace, use the local action:

```yaml
      - uses: ./.github/actions/skillcanary   # if vendored
# or, once the CLI is on npm:
      - run: npx skillcanary scan . --format sarif --fail-on high > findings.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: findings.sarif
```

### Action inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Directory to scan |
| `format` | `sarif` | `sarif`, `json`, or `text` |
| `fail-on` | `high` | Fail at/above `none\|critical\|high\|medium\|low\|info` |
| `rules` | *(all)* | Comma-separated rule IDs |
| `sarif-file` | `$RUNNER_TEMP/skillcanary.sarif` | Report path |
| `upload-sarif` | `true` | Upload to GitHub code scanning |

Output: `sarif-file` (path to the report).

## Any CI (shell)

```bash
npx skillcanary scan . --format sarif --fail-on high > skillcanary.sarif
```

Tolerate known findings while they are being fixed, or drop low-confidence
heuristics:

```bash
npx skillcanary scan . --baseline skillcanary-baseline.json --fail-on high
npx skillcanary scan . --min-confidence medium --fail-on high
```

Exit codes: `0` clean/below threshold, `1` findings at/above `--fail-on`,
`2` usage or IO error.

## Pre-commit

```yaml
- repo: local
  hooks:
    - id: skillcanary
      name: skillcanary
      entry: npx skillcanary scan . --fail-on high --no-color
      language: system
      pass_filenames: false
```

## Notes

- CI should run on a clean checkout; `skillcanary` never executes scanned content.
- Live remote scanning (`--mcp-url`/`--mcp-remote`) makes network calls; keep it
  out of default CI or restrict to trusted endpoints.
- `--scan-packages` downloads tarballs; size-capped and time-limited.
