# MCP server

SkillCanary can run as an MCP server so an agent (Claude Code, Cursor, and other
MCP clients) can scan skills, MCP configs, and packages itself.

```bash
npx skillcanary mcp
```

It speaks newline-delimited JSON-RPC over stdio. It never executes scanned
content; `scan_remote_mcp` makes network calls and is SSRF-guarded.

## Tools

| Tool | Arguments | Purpose |
|---|---|---|
| `scan_path` | `path`, `rules?`, `failOn?` | Scan a directory for risky skills and MCP configs |
| `scan_mcp_config` | `file`, `rules?` | Scan one MCP config file |
| `scan_package` | `spec` | Resolve and scan an npm package or local directory |
| `scan_remote_mcp` | `url`, `allowInsecure?` | Live-scan a remote MCP endpoint |
| `list_rules` | — | List rule IDs |
| `explain_rule` | `id` | Explain one rule |

Every scan tool returns the JSON report (`{ tool, version, summary, findings,
wouldFail }`) as text content and sets `isError` only for real failures (a scan
that finds issues is still a successful tool call).

## Client configuration

Claude Desktop / Cursor style:

```json
{
  "mcpServers": {
    "skillcanary": {
      "command": "npx",
      "args": ["-y", "skillcanary", "mcp"]
    }
  }
}
```

## Skill wrapper

The repo ships [`skills/skillcanary/SKILL.md`](../skills/skillcanary/SKILL.md) so
`SKILL.md`-consuming agents discover the CLI and the MCP server without manual
configuration. Publish it to skills.sh / MCP registries for discovery.
