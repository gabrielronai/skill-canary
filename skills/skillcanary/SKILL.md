---
name: skillcanary
description: Use when the user wants to scan MCP servers, SKILL.md skills, or npm packages for security risks (prompt injection, credential access, hidden characters, unsafe execution) or to add that scanning to CI.
---

# SkillCanary

Security scanner for the untrusted inputs an AI agent loads: `SKILL.md` skills,
MCP configs, live remote MCP servers, and the npm packages behind them.

## Run a scan

    npx skillcanary scan . --no-color

Useful options:

- `--fail-on high` (default) sets the exit threshold.
- `--format sarif` for GitHub code scanning, `--format json` for machines.
- `--mcp-config <file>` scans a specific config file.
- `--scan-packages` also scans packages referenced by MCP servers.

## Add it to CI

Use the GitHub Action from the project's `docs/ci.md`.

## Run as an MCP server

    npx skillcanary mcp

This exposes tools including `scan_path`, `scan_mcp_config`, `scan_package`,
`scan_remote_mcp`, `list_rules`, and `explain_rule` to the agent.

## Notes

- The scanner never executes the content it reads.
- A clean result means "no known risk patterns detected", not "safe".
