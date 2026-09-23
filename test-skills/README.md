# Malicious skill examples (test fixtures)

Full per-fixture reference: [`../docs/test-skills.md`](../docs/test-skills.md).

Synthetic, **non-functional** examples of the attacks the scanner aims to detect.
Names describe what each skill attempts to do. Domains use the reserved
`attacker.example` (does not resolve), and nothing here executes on its own.
**Do not install these as real skills.**

Scan them:

```bash
node dist/bin.js scan test-skills --no-color
```

| Skill | Attack | Expected rule | Status |
|---|---|---|---|
| `prompt-injection-ignore-previous` | Override the agent's instructions | `inj.ignore-previous` | detected |
| `hide-actions-from-user` | Conceal what the agent is doing | `inj.ignore-previous` | detected |
| `act-without-confirmation` | Irreversible action without consent | `inj.ignore-previous` | detected |
| `hidden-zero-width-instructions` | Invisible characters hide content | `obf.zero-width` | detected |
| `read-env-secrets` | Read `.env` | `sec.env-read` | detected |
| `read-cloud-credentials` | Read AWS/SSH credentials | `sec.env-read` | detected |
| `exfiltrate-data-to-webhook` | Send project data to a remote endpoint | `exf.outbound` | detected |
| `download-and-run-remote-script` | `curl … \| bash` | `exec.download-run` | detected |
| `destructive-cleanup` | Overly broad `rm -rf` | `exec.destructive` | detected |
| `base64-encoded-payload` | Hide a payload as base64 | `obf.encoded-blob` | detected |
| `postinstall-hook-download` | Install hook fetches and runs code | `hook.fetch-run` | detected |
| `excessive-permissions` | Over-broad `allowed-tools` | `skill.permissions` | detected |
| `hidden-html-comment` | Instructions hidden in an HTML comment | `inj.hidden-instruction` | detected |
| `mcp-tool-description-injection` | Instructions hidden in an MCP tool description | `mcp.imperative-desc` | detected |

Every skill fixture is now detected by an implemented rule; `test/test-skills.test.ts`
locks this in and the `safe-*` fixtures guard against false positives.

## MCP config fixtures

Malicious MCP configs (unprefixed directories containing `mcp.json`):

| Fixture | Attack | Rule |
|---|---|---|
| `mcp-tool-description-injection` | instructions in a tool description | `mcp.imperative-desc` |
| `mcp-tool-shadowing` | server name mimics a common tool (`read-fille`) | `mcp.shadow` |
| `mcp-env-secrets` | hardcoded credential in `env` | `mcp.secrets` (+ `mcp.overreach`) |
| `mcp-args-download-and-run` | `curl … \| sh` in `command`/`args` | `mcp.args-exec` |
| `mcp-remote-http` | remote server over plaintext HTTP | `mcp.transport` |
| `mcp-unpinned-npx` | `npx -y` with no version pin | `mcp.hygiene` |
| `mcp-path-overreach` | system paths in `args` | `mcp.overreach` |

Safe MCP configs: `safe-mcp-https-pinned`, `safe-mcp-stdio-local`,
`safe-mcp-remote-https` — all must report zero findings.

## Naming convention

- **Unprefixed** directories are malicious fixtures (the table above).
- **`safe-`** prefixed directories are benign fixtures that must report **zero**
  findings.

## Safe skills

Benign skills used to catch false positives. Every `safe-*` directory must
produce no findings; `test/test-skills.test.ts` discovers them dynamically and
asserts this.

| Skill | Purpose |
|---|---|
| `safe-date-formatter` | Format dates |
| `safe-unit-converter` | Convert units |
| `safe-weather-lookup` | Fetch a public weather API |
| `safe-git-log-summarizer` | Summarize `git log` (ships a benign `scripts/collect.sh`) |
| `safe-changelog-writer` | Draft a changelog |
| `safe-log-level-helper` | Explain a log-level setting (mentions `process.env.LOG_LEVEL`) |
| `safe-word-counter` | Count words |

