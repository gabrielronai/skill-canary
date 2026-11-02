# Rule backlog — candidate rules & the harvest process

Status: living document. Started 2026-09-14. Owner: maintainers.

This is where rule ideas are **collected, triaged, and tracked** before they
become code. It exists so the scanner's detection surface can grow with the
attack surface instead of being reinvented each time someone spots a new trick.

- Current shipping ruleset: **33 rules** — list them with `skillcanary rules`.
- This backlog is **not** the rule catalogue; it is the queue feeding it.
- Nothing here is a commitment. An entry is a hypothesis until it passes the
  promotion checklist at the bottom.

Related: [`scanning-rules.md`](./scanning-rules.md) (shipping rules),
[`test-skills.md`](./test-skills.md) (fixtures),
[`../CHANGELOG.md`](../CHANGELOG.md) (what actually shipped).

## How to use this file

1. **Add** candidates during a harvest (or the moment you see a new trick) using
   the template below. One row. Don't wait for a perfect detection idea.
2. **Triage** monthly; move status forward or reject with a reason.
3. **Promote** a candidate only through the promotion checklist — fixture first,
   test first, then code.
4. **Mark shipped** with the version and the live rule ID, then move it to the
   shipped column in the CHANGELOG.

### Status legend

| Status | Meaning |
|---|---|
| `candidate` | Captured, not yet triaged |
| `triaged` | Scored, worth doing, not scheduled |
| `planned` | Scheduled for a specific release |
| `in-progress` | Fixture + implementation underway |
| `shipped` | Live; note version + rule ID |
| `rejected` | Won't do; note why (FP cost, runtime-only, duplicate) |

### Candidate template

```
ID:            <category>.<slug>  (stable; matches the eventual rule id)
Severity:      critical | high | medium | low | info   (proposed)
Confidence:    high | medium | low                      (proposed)
Tier:          A | B | C | D      (see tiers below)
Detects:       one line + a concrete trigger example
Detection:     regex | structural | decode | cross-file | needs-runtime
Data needed:   current model, or the extra field/parser
FP risk:       low | medium | high
Source:        [S#] + link or note
Status:        candidate
```

## Data model available today

Every candidate is scoped against what the scanner can actually see:

- **`FileEntry`** (`src/rules/types.ts`): `path`, `kind` (`skill` | `mcp` |
  `script` | `config`), `content`, `lines`, optional parsed `mcp` and `skill`
  frontmatter.
- **Skill frontmatter**: `name`, `description`, `allowed-tools`.
- **MCP server** (`src/mcp/model.ts`): `name`, `transport`, `command`, `args`,
  `env`, `url`, `headers`, `description`, `tools[].{name, description}`, `line`.
- **Remote MCP**: captured from `initialize` + `tools/list` over Streamable HTTP
  (`src/mcp/remote.ts`).
- **Rules** are pure `check(entry)` functions, **one entry at a time**.

### Tiers

| Tier | Meaning |
|---|---|
| **A** | Drop-in on today's data model (regex/structural). |
| **B** | Needs a small model/parser addition (a field the scanner doesn't capture yet). |
| **C** | Needs a new capability (cross-file pass, new input kind). |
| **D** | Runtime/change detection — needs cross-scan history; out of scope for the static CLI. |

FP risk is the deciding factor on severity in CI: a `high` detection that fires
on clean skills destroys trust faster than a missed trick helps.

---

## Tier A — drop-in candidates

### Injection

| ID | Sev | Detects (trigger) | Detection | FP |
|---|---|---|---|---|
| `inj.decoy-persona` | high | "you are now", "act as", "pretend to be", "developer mode", "DAN", "jailbreak" | regex on persona/override phrasing | med |
| `inj.chat-template-spoof` | high | `[INST]`, `### System`, `<\|system\|>`, `<\|im_start\|>`, line-leading `system:` | regex | low |
| `inj.delayed-trigger` | medium | "when the user asks about X", "on the next run", "after N messages", "if the date is…" | regex: event/time conditional near an action verb | med |
| `inj.hidden-markup` | high | `[//]: # (…)`, `display:none`, white-on-white, `font-size:0`, `visibility:hidden`, collapsed `<details>` | regex over markdown/HTML | med |
| `inj.approval-bypass` | medium | "auto-approve", "skip confirmation", "without review", "proceed without asking" | regex (extends no-confirmation phrasing) | med |
| `inj.data-embed-directive` | high | "base64-encode the key and append it to the URL", "put the token in the filename" | verb + secret + transport co-occurrence | med |
| `inj.role-escalation` | medium | "assume admin", "grant yourself", "you now have permission", "elevate privileges" | regex | med |

### Obfuscation

| ID | Sev | Detects (trigger) | Detection | FP |
|---|---|---|---|---|
| `obf.ansi-escape` | high | raw ESC/CSI/OSC sequences in skill text (terminal spoofing) | control-char scan | low |
| `obf.control-chars` | medium | C0/C1 controls other than `\n`, `\r`, `\t` | codepoint scan | low |
| `obf.entity-encoded` | medium | `&#105;gnore` / `&Tab;` decoding to keywords | decode entities → keyword scan | low |
| `obf.percent-encoded` | medium | `%69%67%6e%6f%72%65` decoding to keywords | percent-decode → keyword scan | low |
| `obf.hex-escape` | medium | `\x69\x67\x6e\x6f\x72\x65` decoding to keywords | unescape → keyword scan | low |
| `obf.whitespace-stego` | low | long trailing space/tab runs encoding bits | run-length analysis | med |
| `obf.nested-blob` | medium | decoded blob instructs decoding another blob | iterative decode with depth cap | med |
| `obf.punycode-host` | medium | `xn--` / IDN homograph hosts in URLs | URL host scan | low |
| `obf.emoji-vs` | low | variation-selector stego appended to emoji | codepoint scan | high |

### Secrets & credential access

| ID | Sev | Detects (trigger) | Detection | FP |
|---|---|---|---|---|
| `sec.env-var` | medium | references to `*_KEY`, `*_TOKEN`, `*_SECRET`, `AWS_*` env vars | regex on env access (the deferred split from `sec.env-read`) | low |
| `sec.env-dump` | high | `printenv`, `env`, `set`, `Get-ChildItem Env:`, `/proc/self/environ` | regex | low |
| `sec.wallet-access` | high | MetaMask/keystore/`wallet.dat`/seed-phrase paths | regex | low |
| `sec.credential-store` | high | kubeconfig, `.git-credentials`, `.docker/config.json`, `.gnupg`, `.pgpass`, `.terraform`, shell history | path regex (extends today's list) | low |
| `sec.clipboard-keychain` | medium | `xclip`, `pbpaste`, `Get-Clipboard`, `security find-generic-password`, `login.keychain-db` | regex | med |
| `sec.private-key-material` | high | `-----BEGIN … PRIVATE KEY-----` blocks | regex | low |

### Exfiltration

| ID | Sev | Detects (trigger) | Detection | FP |
|---|---|---|---|---|
| `exf.dns` | high | `dig`/`nslookup`/`host` with base64-looking labels | regex + label entropy | med |
| `exf.cloud-upload` | high | `aws s3 cp`, `gsutil cp`, `az storage`, `rclone copy` of local files | regex | med |
| `exf.mail-send` | medium | `sendmail`, `mail -s`, SMTP libs sending file/secret content | regex | med |
| `exf.beacon-image` | medium | `![](http://…?data…)` or `<img src>` with payload in query | markdown/HTML image scan | med |
| `exf.chat-api` | high | `api.telegram.org/bot…/sendMessage`, Slack/Discord bot posts | regex | low |
| `exf.env-to-net` | high | request URL/body references `$SECRET` / `${TOKEN}` / env vars | co-occurrence | med |
| `exf.dynamic-encoded-upload` | high | `base64 file \| curl -d @-`, `xxd \| nc` | pipeline regex | med |

### Execution

| ID | Sev | Detects (trigger) | Detection | FP |
|---|---|---|---|---|
| `exec.privesc` | high | `sudo`, `doas`, `pkexec`, `chmod u+s`, `setcap`, `runas` | regex | med |
| `exec.persistence` | high | `crontab -`, `~/.bashrc`/`.zshrc` append, LaunchAgents, systemd unit, registry `Run`, Startup folder | regex + path | med |
| `exec.miner` | high | `xmrig`, `stratum+tcp://`, Monero pools, `--donate-level` | regex | low |
| `exec.encoded-shell` | critical | `powershell -enc`, `pwsh -EncodedCommand`, `base64 -d \| sh` | regex | low |
| `exec.temp-exec` | high | write to `/tmp`/`$TMPDIR` → `chmod +x` → run | multi-line pipeline | med |
| `exec.git-hook-write` | high | writes `.git/hooks/*` or sets `core.hooksPath` | path/arg regex | med |
| `exec.downloader-chain` | high | `wget -O f && chmod +x f && ./f` | adjacent-command analysis | med |

### Supply chain, hooks & packages

| ID | Sev | Detects (trigger) | Detection | FP |
|---|---|---|---|---|
| `hook.network-call` | medium | lifecycle hook making any network call (`fetch`, `http.get`, `Invoke-RestMethod`), not just `curl \| sh` | broaden `hook.fetch-run` to all network verbs | med |
| `hook.script-chain` | medium | lifecycle hook invoking a bundled script (`node ./x`, `sh ./x`) | regex on hook body | med |
| `pkg.typosquat` | high | dependency/package name within 1–2 edits of a popular package | needs popular-name list | med |
| `pkg.dep-confusion` | high | internal-looking scoped name resolved from the public registry | heuristic + registry lookup | med |
| `pkg.install-script` | info | dependency ships install scripts | read dependency `package.json` | low |
| `pkg.non-registry` | high | lockfile `resolved` not on the npm registry (IP/git/http) | lockfile parse | low |
| `pkg.unpinned-git` | medium | `git+https…` dependency without `#<sha>` | manifest/lock parse | low |
| `pkg.remote-tarball` | medium | `http(s)://…tgz` dependency | manifest parse | low |
| `pkg.binary-asset` | info | package ships large/prebuilt binaries (ELF/PE/Mach-O) | file sniff | low |

### Skill hygiene & format

| ID | Sev | Detects (trigger) | Detection | FP |
|---|---|---|---|---|
| `skill.name-mismatch` | low | frontmatter `name` ≠ directory, or missing | frontmatter check | low |
| `skill.no-description` | info | missing/empty `description` | frontmatter | low |
| `skill.external-instructions` | high | instructs fetching a remote `SKILL.md`/policy at runtime | URL + "fetch/load rules" co-occurrence | med |
| `skill.oversized` | low | `SKILL.md` beyond N KB / lines (context poisoning) | size check | med |
| `skill.duplicate-frontmatter` | medium | duplicate YAML keys / merge tricks | YAML parse warnings | low |

### MCP

| ID | Sev | Detects (trigger) | Detection | FP |
|---|---|---|---|---|
| `mcp.command-wrapper` | medium | command is `sh`/`bash -c`/`cmd /c`/`pwsh -c` | command + args regex | med |
| `mcp.binary-path` | medium | command/args reference `/tmp`, `~/.cache`, world-writable or absolute temp paths | path regex | med |
| `mcp.unicode-name` | high | non-ASCII/homoglyph server/tool names | codepoint scan (extends `mcp.shadow`) | low |
| `mcp.many-tools` | info | server exposes an unusually large tool set | count threshold | med |
| `mcp.resource-overreach` | medium | `file://` or broad-glob resources exposed | parse `resources` | med |

---

## Tier B — needs a small model addition

| ID | Sev | Detects (trigger) | Needs | FP |
|---|---|---|---|---|
| `mcp.instructions-field` | high | MCP `initialize.instructions` contains imperative text | capture `instructions` from the initialize result | med |
| `mcp.dynamic-tools` | high | `tools/list` differs between two calls (change/rug-pull signal) | a second `tools/list` call + compare | med |
| `mcp.oauth-scope-broad` | medium | broad/`*` OAuth scopes requested in a config | parse the auth/headers block | med |

---

## Tier C — needs a new capability

Cross-file **correlated** rules (require the global pass, enabler E2):

| ID | Sev | Detects (trigger) | FP |
|---|---|---|---|
| `corr.secret-to-network` | critical | the same artifact reads a secret and sends outbound | med |
| `corr.download-and-persist` | high | downloads code **and** installs persistence | med |
| `corr.obfuscation-plus-exec` | high | encoded blob **plus** dynamic execution in one artifact | med |
| `corr.shadow-plus-secret` | high | MCP tool shadowing **plus** a secret env var in one config | med |

New **input kind** (enabler E7) — the scanner currently ignores agent
instruction files, which are the same untrusted-instruction surface as
`SKILL.md`. Once discovered as `kind: "instructions"`, the existing injection and
obfuscation rules run against them unchanged:

- `CLAUDE.md`, `AGENTS.md`
- `.cursor/rules/*.mdc`, `.github/copilot-instructions.md`
- `.continue/config.json`, aider / Cline rule files

(No new rule IDs — reuse `inj.*` / `obf.*`.)

---

## Tier D — runtime/change detection

Not static-rule work; these need cross-scan history and are out of scope for the CLI.

| ID | Sev | Detects |
|---|---|---|
| `run.rug-pull` | critical | an artifact/tool-list silently changes after first approval |
| `run.tool-list-diff` | high | MCP tools added/changed between scans |
| `run.artifact-drift` | high | skill/package hash change between versions |

---

## Extensions to existing rules (no new ID)

Cheaper than new rules — widen a pattern list or a detection:

- `obf.zero-width` — also scan frontmatter/metadata fields, and decode + print
  the hidden text instead of only flagging it.
- `skill.permissions` — flag wildcard `*`, tool-count thresholds, and
  network+write combinations, not just the fixed broad-tool list.
- `mcp.transport` — flag raw-IP hosts and non-standard ports (beyond plaintext
  HTTP and loopback).
- `hook.fetch-run` — superseded in scope by `hook.network-call` (Tier A).
- `sec.env-read` — keep; `sec.env-var` splits out the `*_KEY`/`*_TOKEN` case.

---

## Enablement backlog (prerequisites, not rules)

These make rule growth cheap and safe. Tracked here; built separately.

| ID | Item | Why it matters now |
|---|---|---|
| **E1** | Shared `src/rules/patterns.ts` | Pattern lists are duplicated (`IMPERATIVE_PATTERNS`, `DOWNLOAD_RUN_PATTERNS`); one source prevents drift as the catalogue grows. |
| **E2** | Optional global pass `checkAll(entries)` | The per-entry `Rule.check` cannot express `corr.*` rules. Additive interface change. |
| **E5** | FP corpus harness | Scan a pinned set of real public skills/MCP configs (never executed), snapshot findings, fail on new ones. Catches false positives **and** mints new candidates. |
| **E6** | This doc + the harvest cadence below | The collection process itself. |

Recommended order: **E1 → E5 → E2**.

---

## Harvest process

### Cadence

| Trigger | When | Output |
|---|---|---|
| **Harvest** | Monthly, 30–60 min | New `candidate` rows added |
| **Triage + release** | Quarterly (aligns with the overview's "re-evaluate quarterly") | Candidates scored; top ones promoted; minor version bumped |
| **Incident** | Same week a public MCP/skill compromise lands | A candidate + fixture the same week |

### Feeds to watch

- **Standards & frameworks:** [S1] OWASP Top 10 for LLM Apps (LLM01, LLM03,
  LLM06, LLM07), [S2] MITRE ATLAS, [S14] NIST AI 600-1.
- **Advisories:** [S3] OSV.dev + GitHub Advisory Database; [S4] Snyk / Socket /
  Trail of Bits / Aikido blogs filtered for MCP, skills, and prompt injection.
- **Formats (new surfaces):** [S5] MCP specification + changelog; [S6] Anthropic
  Agent Skills and Claude Code docs; [S7] Cursor / Windsurf / Cline / Continue
  rule-file docs. A new field or file format is a new attack surface.
- **Research & practitioners:** [S8] Embrace The Red, [S9] Simon Willison,
  [S12] r/mcp, r/netsec, r/AI_Agents, Hacker News.
- **Ecosystem:** [S10] skills.sh / MCP-registry new-listing feeds; [S13]
  Hugging Face security advisories.
- **Pattern reuse:** [S11] gitleaks / trufflehog / detect-secrets / Semgrep rule
  sets — borrow detection ideas, don't reinvent them.
- **Our own telemetry:** GitHub issues, false-positive reports, `explain` usage.

### Triage rubric

Score each candidate 1–5, then decide:

| Factor | Question |
|---|---|
| Detectability | Can static text/structure catch it (5) or is it runtime-only (1)? |
| Impact | How bad if exploited? |
| FP cost | How often does it fire on clean skills? (inverse) |
| Effort | Drop-in pattern (5) vs new parser (1)? |
| Overlap | Does it duplicate or extend an existing rule? |

Decision: **promote** (new rule) · **extend** (widen an existing rule) ·
**defer** (keep as `triaged`) · **reject** (runtime-only, FP-heavy, or duplicate).

### Promotion checklist (definition of done)

A candidate only ships when all of these are true:

1. A malicious fixture exists in `test-skills/<intent>/` using `attacker.example`
   — plus a `safe-*` fixture if the rule is FP-prone.
2. The rule is implemented in `src/rules/<category>.ts` with a stable ID,
   severity, confidence, message, and remediation.
3. A unit test asserts **≥1 positive and ≥1 negative** (`test/rules-*.test.ts`).
4. `docs/test-skills.md` is updated, and `npm run gen:rules` refreshes
   `docs/rules.json` (the registry test fails if docs drift).
5. `npm run check` and `npm run selfscan` are green, and the FP corpus (E5)
   shows no new findings.
6. `CHANGELOG.md` has an entry and the version is bumped.

### FP governance

- Prefer false negatives over alert fatigue — the existing tuning principle.
- New rules default to `medium`/`low` confidence until the FP corpus and field
  reports justify more.
- Users have an escape hatch: inline `# skillcanary:ignore`, `--baseline`, and
  `--min-confidence` (E3). High-FP rules can ship, but still need a `safe-*`
  fixture and a clean self-scan.

### Versioning

- `CHANGELOG.md` (Keep a Changelog). Ruleset changes are **minor** bumps; only
  breaking changes (removing/renaming a rule ID, or a severity change that flips
  CI pass/fail) justify a **major** at `1.0+`.
- Document severity changes explicitly — they change CI outcomes for pinned
  users.
- Consider surfacing a `ruleset` identifier in `skillcanary --version` so users
  can reference "which rules" they ran.
- `--rules` remains the adoption tool: users can pin a set while evaluating a
  noisy new rule.

### Metrics

- Candidates harvested / triaged / shipped per quarter.
- FP reports per 1,000 scans; median time-to-fix for a reported FP.
- Fixture coverage: every shipped rule has ≥1 fixture and ≥1 negative test.

---

## Sources

- **S1** OWASP Top 10 for LLM Applications — https://genai.owasp.org/llm-top-10/
- **S2** MITRE ATLAS — https://atlas.mitre.org/
- **S3** OSV.dev — https://osv.dev/ ; GitHub Advisory Database — https://github.com/advisories
- **S4** Snyk, Socket, Trail of Bits, Aikido security research blogs
- **S5** Model Context Protocol specification — https://modelcontextprotocol.io/
- **S6** Anthropic Agent Skills — https://docs.anthropic.com/
- **S7** Cursor / Windsurf / Cline / Continue rule-file documentation
- **S8** Embrace The Red (Johann Rehberger) — https://embracethered.com/
- **S9** Simon Willison's Weblog — https://simonwillison.net/
- **S10** skills.sh and MCP registries (new-listing feeds)
- **S11** gitleaks, trufflehog, detect-secrets, Semgrep rule sets
- **S12** r/mcp, r/netsec, r/AI_Agents, Hacker News
- **S13** Hugging Face security advisories — https://huggingface.co/docs/hub/security
- **S14** NIST AI 600-1 (Generative AI Profile)
