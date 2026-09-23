# SkillCanary

A security scanner for **MCP servers** and **`SKILL.md` skills** — the untrusted
inputs an AI agent loads before it runs. It reports prompt injection, hidden
characters, credential access, dangerous execution, exfiltration, and install-hook
and supply-chain risks, then fails your build at a threshold you choose.

Static heuristics only: deterministic, offline by default, no API keys, and it
never executes the content it scans.

## Status

**v0.1.0 — pre-release, not yet on npm.** Working: 24 rules across injection,
obfuscation, secrets, execution, exfiltration, install hooks, skill hygiene, and
MCP (structural + live remote); discovery of skills, MCP configs, scripts, and
`package.json` hooks; text/JSON/SARIF output; remote MCP and npm/local package
scanning; a composite GitHub Action; and an MCP server wrapper. 75 tests, self-scan
clean. Not yet: npm publish.

## Requirements

- Node.js >= 20

## Usage

From a checkout:

```bash
npm install
npm run build
node dist/bin.js scan .            # scan the current directory
node dist/bin.js rules             # list rules
node dist/bin.js explain sec.env-read
```

Options:

```
scan [path] [options]
  --format <text|json|sarif>  Output format (default text)
  --fail-on <level>           Exit 1 at/above: none|critical|high|medium|low|info (default high)
  --rules <id,id>             Only run these rules
  --mcp-url <url>             Also scan a remote MCP server live (opt-in, repeatable)
  --mcp-remote                Live-scan remote servers found in configs
  --package <spec>            Scan an npm package or local dir (never executed)
  --scan-packages             Scan packages referenced by MCP servers
  --no-color                  Disable color
  --quiet                     Suppress the report (exit code only)
  -h, --help                  Help
  -v, --version               Version
```

Exit codes: `0` clean or below threshold, `1` findings at/above `--fail-on`,
`2` usage or IO error.

### Ignoring paths

Add a `.scannerignore` at the scan root, one path prefix per line (`#` comments
allowed):

```
vendor
test/fixtures
```

## Rules

24 rules across injection (`inj.*`), obfuscation (`obf.*`), secrets (`sec.*`),
execution (`exec.*`), exfiltration (`exf.*`), install hooks (`hook.*`), skill
hygiene (`skill.*`, `hygiene.*`), and MCP (`mcp.*`). List them with
`node dist/bin.js rules` or explain one with
`node dist/bin.js explain <rule-id>`.

## Development

```bash
npm run typecheck   # tsc --noEmit
npm run lint        # biome check
npm run lint:fix    # biome check --write
npm test            # vitest
npm run build       # tsc -> dist
npm run selfscan    # scan this repo; must be clean
npm run check       # typecheck + lint + test
```

## Safety

Scanned content is untrusted. The scanner never executes, imports, or fetches it;
regexes are bounded; all output strips ANSI/control characters and redacts
likely secrets. Package scanning extracts an npm tarball to a temp directory and
never runs install scripts. Remote MCP scanning is opt-in and behind an SSRF
guard; by default there is no network access.

## License

Apache-2.0 (see [`LICENSE`](LICENSE)).

## Project docs

- [`docs/usage.md`](docs/usage.md) — how to run it, and how to test it on real
  skills / MCP configs
- [`docs/commands.md`](docs/commands.md) — copy-paste commands for cmd.exe,
  PowerShell, Linux, and macOS
- [`docs/ci.md`](docs/ci.md) — GitHub Action and other CI integration
- [`docs/npm.md`](docs/npm.md) — publishing to npm
- [`docs/mcp-server.md`](docs/mcp-server.md) — run as an MCP server; ships a
  `skills/skillcanary/SKILL.md` wrapper
- [`docs/test-skills.md`](docs/test-skills.md) — reference for the malicious
  fixtures in `test-skills/`
- [`docs/scanning-rules.md`](docs/scanning-rules.md) — the rule model, the 24
  rules, and how they are configured
- [`docs/rule-backlog.md`](docs/rule-backlog.md) — candidate rules and the
  process for adding them
