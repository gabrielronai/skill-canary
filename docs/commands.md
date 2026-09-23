# Command reference (Windows, Linux, macOS)

Copy-paste commands for running the scanner in each shell. See
[`usage.md`](./usage.md) for what it scans and how to read output.

The CLI is not published to npm yet, so commands run the built file
(`dist/bin.js`). Once published it becomes `npx <pkg> scan <path>`.

## One-time setup (all shells)

Run from the project root:

```bash
npm install
npm run build
```

## cmd.exe (Windows)

Use `%USERPROFILE%` and `%APPDATA%`.

```bat
REM installed skills
node dist\bin.js scan "%USERPROFILE%\.agents\skills" --no-color
node dist\bin.js scan "%USERPROFILE%\.claude\skills" --no-color

REM current project
node dist\bin.js scan . --no-color

REM Claude Desktop MCP config directory
node dist\bin.js scan "%APPDATA%\Claude" --no-color

REM other commands
node dist\bin.js rules
node dist\bin.js explain sec.env-read
node dist\bin.js scan . --fail-on high
echo %ERRORLEVEL%
```

## PowerShell (Windows)

Use `$HOME` (expands to `C:\Users\<you>`) inside **double** quotes. Single
quotes do **not** expand variables.

```powershell
# installed skills
node .\dist\bin.js scan "$HOME\.agents\skills" --no-color
node .\dist\bin.js scan "$HOME\.claude\skills" --no-color

# current project
node .\dist\bin.js scan . --no-color

# Claude Desktop MCP config directory
node .\dist\bin.js scan "$HOME\AppData\Roaming\Claude" --no-color

# other commands
node .\dist\bin.js rules
node .\dist\bin.js explain sec.env-read
node .\dist\bin.js scan . --fail-on high
$LASTEXITCODE
```

## Linux and macOS (bash / zsh)

Use `~` or `$HOME`.

```bash
# installed skills
node dist/bin.js scan ~/.agents/skills --no-color
node dist/bin.js scan ~/.claude/skills --no-color

# current project
node dist/bin.js scan . --no-color

# Claude Desktop MCP config directory
node dist/bin.js scan "$HOME/Library/Application Support/Claude" --no-color   # macOS
node dist/bin.js scan "$HOME/.config/Claude" --no-color                        # Linux

# other commands
node dist/bin.js rules
node dist/bin.js explain sec.env-read
node dist/bin.js scan . --fail-on high
echo $?
```

## Scan a public skills repository (any shell)

```bash
git clone https://github.com/anthropics/skills.git /tmp/skills-repo
node dist/bin.js scan /tmp/skills-repo --no-color
```

Install with the ecosystem installer, then scan where skills land
(`~/.claude/skills/<name>`):

```bash
npx skills add anthropics/find-skills
node dist/bin.js scan ~/.claude/skills --no-color
```

## Scan a remote MCP server (any shell)

Live-scans an endpoint over MCP Streamable HTTP (network access, opt-in):

```bash
node dist/bin.js scan . --mcp-url https://mcp.example.com/mcp --no-color
node dist/bin.js scan . --mcp-url https://mcp.example.com/mcp --mcp-header "Authorization: Bearer $MCP_TOKEN" --no-color
node dist/bin.js scan . --mcp-remote --no-color          # live-scan servers found in configs
```

Plaintext `http://` and private/loopback hosts are refused by the SSRF guard;
add `--allow-insecure` for local testing only.

## Scan a specific MCP config file (any shell)

```bash
node dist/bin.js scan . --mcp-config "$HOME/.cursor/mcp.json" --no-color
```

## Scan a package (any shell)

Resolves and scans a package an MCP server runs (or one you name); never
executes package code.

```bash
node dist/bin.js scan . --package some-helper@1.2.3 --no-color   # npm
node dist/bin.js scan . --package ./packages/my-mcp --no-color   # local directory
node dist/bin.js scan . --scan-packages --no-color               # packages referenced by MCP servers
node dist/bin.js scan . --scan-packages --package-max-mb 5 --no-color
```

## Where the paths point

| What | Windows | Linux / macOS |
|---|---|---|
| Codex CLI skills (user) | `%USERPROFILE%\.agents\skills` | `~/.agents/skills` |
| Claude Code skills (user) | `%USERPROFILE%\.claude\skills` | `~/.claude/skills` |
| Project-scoped skills | `.claude\skills`, `.github\skills`, `.agents\skills`, `.skills` | `.claude/skills`, `.github/skills`, `.agents/skills`, `.skills` |
| Claude Desktop MCP config dir | `%APPDATA%\Claude` | `~/Library/Application Support/Claude` (macOS), `~/.config/Claude` (Linux) |
| Cursor MCP config dir | `%USERPROFILE%\.cursor` | `~/.cursor` |

Point the scanner at a **directory**; it finds every `SKILL.md` and MCP config
beneath it.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No findings, or none at/above `--fail-on` |
| 1 | At least one finding at/above `--fail-on` (default `high`) |
| 2 | Usage or IO error (bad path, unknown option, unsupported format) |

Read the code immediately after the command: `$LASTEXITCODE` (PowerShell),
`%ERRORLEVEL%` (cmd), `echo $?` (bash/zsh).

## Notes

- **Path with spaces** (e.g. `Application Support`): quote it.
- **`Not a directory: $env:USERPROFILE\...`** — the shell did not expand the
  variable. Use `$HOME` (PowerShell/bash) or `%USERPROFILE%` (cmd) inside double
  quotes. The CLI prints this hint when a path still contains `$env:` or
  `%USERPROFILE%`.
- **`npm install` allow-scripts warning** — expected; `.npmrc` sets
  `ignore-scripts=true` on purpose (binaries come from optional platform
  packages).
