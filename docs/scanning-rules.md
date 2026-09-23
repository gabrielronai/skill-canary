# The ruleset: how rules are built and configured

Reference for SkillCanary's detection rules. For the process of *adding* rules,
see [`rule-backlog.md`](./rule-backlog.md).

## Rule model

A rule is a pure function over one pre-read file. No I/O, no network, no
execution of scanned content — that is what makes the scan deterministic and
testable.

**`src/rules/types.ts`**

- `Rule` = `{ id, severity, confidence, description, kinds?, check(entry) }`.
  `check` returns `Finding[]`.
- `Finding` = `{ ruleId, severity, confidence, message, file, line?, column?,
  snippet?, remediation? }`.
- `Severity` = `critical | high | medium | low | info`;
  `Confidence` = `high | medium | low`.
- `FileKind` = `skill | mcp | script | config | other`; `kinds` scopes a rule to
  file kinds.
- `meetsThreshold` compares a finding's severity to the `--fail-on` level
  (`none` never fails).

**`FileEntry`** (the input each rule sees) carries `path`, `kind`, `content`,
`lines`, plus parsed `mcp?` (for `kind: "mcp"`) and `skill?` frontmatter
(`name`, `description`, `allowedTools`) for `kind: "skill"`.

### Registration and execution (`src/rules/registry.ts`)

- Rules are listed in `ALL_RULES` in reporting order; `ALL_RULE_IDS` is derived
  from it.
- `runRules` loops entries × rules, skips a rule when `rule.kinds` does not
  include the entry kind (`appliesTo`), wraps `check` in try/catch (a
  misbehaving rule is skipped, never fatal), and dedups on
  `ruleId|file|line|message`.
- `sortFindings` (`src/scan.ts`) orders by severity desc, then file, then line.
- `evaluate(entries, { rules })` =
  `sortFindings(runRules(entries, selectRules(rules)))`.

## The 24 rules

| Rule | Sev | Conf | `kinds` | Detection |
|---|---|---|---|---|
| `inj.ignore-previous` | high | medium | all | line regex over `IMPERATIVE_PATTERNS` (ignore/disregard previous instructions, "do not tell the user", "without asking") |
| `inj.hidden-instruction` | high | low | all | instruction keywords inside HTML comments (`<!-- … -->`) |
| `inj.system-prompt` | medium | low | all | reveal/replace/ignore + "system prompt / your instructions" |
| `obf.zero-width` | high | high | all | zero-width/bidi format chars (`hasFormatChars`), snippet escaped as `\uXXXX` |
| `obf.encoded-blob` | high | med/low | all | base64 (>= 40 chars) decoded and keyword-scanned; hex (>= 64) is lower confidence |
| `obf.homoglyph` | medium | low | all | one token mixing Latin + Cyrillic/Greek (confusables) |
| `sec.env-read` | high/med | medium | all | `.env`, AWS/SSH/gcloud/netrc/npmrc/keychain/cookies → high; secret-looking env access → medium |
| `exec.destructive` | high | medium | skill, script, config | `rm -rf`, `mkfs`, `dd`, fork bomb, `chmod -R 777`, `shred`, `/dev/sd*` |
| `exec.download-run` | critical | high | skill, script, config | `curl \| sh`, `iwr \| iex`, `bash <(curl …)` |
| `exec.dynamic` | medium | low | skill, script, config | `eval(`, `exec(`, `new Function`, `child_process`, `os.system`, `popen` |
| `exf.outbound` | critical | medium | skill, script, config | a URL **and** a send verb/form in the same file (`curl -d/-F`, `requests.post`, `fetch(`, `scp`) |
| `exf.webhook` | high | high | skill, script, config | known endpoints (Discord webhooks, webhook.site, requestbin, ngrok, interact.sh, OAST, Canarytokens…) |
| `hook.fetch-run` | high | medium | config (`package.json`) | install hooks (`preinstall/install/postinstall/prepare`) that fetch or exec code |
| `skill.permissions` | medium | low | skill | frontmatter `allowed-tools` containing broad tools (`bash`, `write`, `webfetch`, `*`…) |
| `hygiene.unpinned` | low | medium | skill, script | `npx/uvx/bunx -y <pkg>` with no `@version` |
| `hygiene.http` | low | low | skill, script, config | plaintext `http://` that is not localhost |
| `mcp.invalid` | info | high | mcp | config failed to parse |
| `mcp.imperative-desc` | high | medium | mcp | instruction language in server/tool descriptions |
| `mcp.shadow` | high | medium | mcp | server/tool name within one edit of a canonical tool (`readfile`, `bash`, …) |
| `mcp.overreach` | medium | medium | mcp | secret-like `env` keys, or home/system paths in command/args |
| `mcp.args-exec` | high | medium | mcp | `command`/`args` with `curl \| sh`, `bash -c`, `-enc`, `rm -rf`, `iex` |
| `mcp.transport` | medium | med/high | mcp | plaintext `http://` remote URL, or loopback/IP-literal host |
| `mcp.secrets` | high | medium | mcp | hardcoded credential-shaped value in `env`/`headers` (placeholder-aware, redacted) |
| `mcp.hygiene` | low | medium | mcp | `npx/uvx/pnpm/bunx` server arg with no version pin |

Notes: `config` currently means `package.json` only. Injection, obfuscation, and
secret-access rules run on every recognized kind; execution, exfiltration, hooks,
permissions, and hygiene are kind-scoped; all `mcp.*` are `mcp`-only.

## How content reaches rules

`src/scan.ts` walks the tree and classifies each file (`classify`):

- `SKILL.md` → `skill`
- known MCP config filenames → `mcp`
- `package.json` → `config`
- script extensions inside a skill directory → `script`
- everything else is dropped

`buildEntry` attaches the parsed MCP config (`src/mcp/parse.ts`) and skill
frontmatter (`src/inputs/skills.ts`). Remote scans synthesize
`{ path: "mcp://host", kind: "mcp", mcp }` (`remoteEntry`), so the same rules
apply.

## Configuration

All configuration is per-invocation flags plus `.scannerignore`. There is **no
config file** (the `scanner.config.json` in the original plan was never built).

- `--rules <id,id>` — restrict to given rule IDs. Unknown IDs are silently
  ignored (`selectRules` filters; no validation error).
- `--fail-on <none|critical|high|medium|low|info>` — default `high`; controls
  the exit code only (the report is still printed). Exit `0` below threshold,
  `1` at/above, `2` usage/IO error.
- `--format text|json|sarif`, `--quiet`, `--no-color`.
- MCP and packages: `--mcp-config`, `--mcp-url`, `--mcp-remote`,
  `--mcp-header`, `--allow-insecure`, `--package`, `--scan-packages`,
  `--package-max-mb`. `--scan-packages` derives specs from MCP server commands.
- `.scannerignore` at the scan root: one path prefix per line, `#` comments.
  Matching is prefix-based (`rel === entry || rel.startsWith(entry + "/")`). This
  is the only suppression mechanism today.
- Built-in walk limits (`src/inputs/walk.ts`): skips `.git`, `node_modules`,
  `dist`, `build`, `out`, `coverage`, `vendor`, virtualenvs, caches; skips binary
  extensions; skips files > 1 MB; drops content containing NUL.
- Output safety (`src/util/text.ts`): every snippet passes `toSafeSnippet` —
  strip ANSI + format chars, collapse whitespace, `redactSecrets` (`sk-`,
  `ghp_`, `AKIA`, `AIza`, `xox*`, private-key headers), truncate to 200 chars.

## How a rule is added

Per the [`rule-backlog.md`](./rule-backlog.md) promotion checklist:

1. A malicious fixture in `test-skills/<intent>/` using `attacker.example`
   (plus a `safe-*` fixture if the rule is FP-prone).
2. Implementation in `src/rules/<category>.ts` with a stable `ruleId`, severity,
   confidence, message, and remediation.
3. A unit test with >= 1 positive and >= 1 negative
   (`test/rules/*.test.ts`, `test/rules-m1.test.ts`).
4. Docs/rule-table update and a `CHANGELOG.md` entry.
5. `npm run check && npm run selfscan` green.

## Known gaps (backlog, not implemented)

- No inline `# skillcanary:ignore` comments, no baseline file, no
  confidence-gated CI (backlog item **E3**, flagged as a prerequisite before
  shipping any high-FP rule).
- No shared pattern module — `IMPERATIVE_PATTERNS`, `DOWNLOAD_RUN_PATTERNS` are
  duplicated (**E1**).
- Rule tables in README/site are hand-copied from `rules` output and can drift;
  no machine-readable registry feeds them (**E4**).
- Rules are per-entry only; no cross-file `corr.*` pass (**E2**), no
  instruction-file discovery (`AGENTS.md`, `CLAUDE.md`) (**E7**), no FP corpus
  harness (**E5**).
