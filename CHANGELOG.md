# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Ruleset changes (added/removed rules, severity changes) are called out
explicitly, since they can change whether a build passes.

## [Unreleased]

## [0.2.0] - 2026-11-02

### Added

- **9 rules (33 total):** `exf.secret-to-network`, `exf.base-url-hijack`,
  `obf.unicode-tag`, `exec.reverse-shell`, `exec.security-disable`,
  `sec.hardcoded-secret`, `agent.hook-exec`, `agent.unsafe-setting`, and
  `mcp.schema-injection`.
- **Agent config scanning:** `.claude/settings.json`,
  `.claude/settings.local.json`, and `.claude/hooks/hooks.json` are classified as
  `agentconfig` and checked for auto-run hooks and unsafe settings.
- **Instruction files:** `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`,
  `.windsurfrules`, `.clinerules`, `.cursor/rules/*.mdc`, and
  `.github/copilot-instructions.md` are classified as `instructions` and run
  through the injection, obfuscation, secret, and execution rules.
- **MCP input schemas:** tool `inputSchema` descriptions/defaults/enums are
  captured and scanned by `mcp.schema-injection`.

### Changed

- `sec.env-read` now also covers kube/docker config, shell history, and
  `/etc/passwd`/`/etc/shadow`.
- `exf.webhook` now recognizes common paste services.
- Execution and exfiltration rules also apply to `instructions` and
  `agentconfig` files.
- **98 tests**, self-scan clean.

Candidate rules and the plan for growing the ruleset are tracked in
[`docs/rule-backlog.md`](docs/rule-backlog.md).

## [0.1.0] - 2026-09-23

Initial pre-release. Not yet published to npm.

### Added

- **Scanner core:** deterministic, offline discovery and scanning of `SKILL.md`
  skills, MCP configs (all common shapes), scripts inside skill directories, and
  `package.json` install hooks.
- **24 rules** across injection (`inj.*`), obfuscation (`obf.*`), secrets
  (`sec.*`), execution (`exec.*`), exfiltration (`exf.*`), install hooks
  (`hook.*`), skill hygiene (`skill.*`, `hygiene.*`), and MCP (`mcp.*`).
- **Output formats:** text, JSON, and SARIF 2.1.0.
- **Exit codes:** `0` clean/below threshold, `1` findings at/above `--fail-on`
  (default `high`), `2` error.
- **Remote MCP scanning** (`--mcp-url`, `--mcp-remote`) behind an SSRF guard;
  local servers are never spawned.
- **Package scanning** (`--package`, `--scan-packages`): npm tarball or local
  directory, extracted to a temp dir, never executed.
- **GitHub Action** (`action.yml`, composite) that builds the scanner and
  uploads SARIF to GitHub code scanning.
- **MCP server** (`skillcanary mcp`) exposing the scanner to agents, with a
  shipped `skills/skillcanary/SKILL.md` wrapper.
- **CLI:** `scan`, `rules`, `explain`, `mcp`; `.scannerignore` support; secret
  redaction and control-character stripping in all output.
- **74 tests**, self-scan clean, CI (`typecheck → lint → test → build →
  selfscan`).

### Documentation

- Usage/command/CI/npm docs, the MCP-server guide, the fixture reference, the
  rule reference, and the rule backlog + harvest process.

[Unreleased]: https://github.com/gabrielronai/skill-canary/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/gabrielronai/skill-canary/releases/tag/v0.2.0
[0.1.0]: https://github.com/gabrielronai/skill-canary/releases/tag/v0.1.0
