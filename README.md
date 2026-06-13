# AI Agent Inventory

Claude Code / Codex のローカル設定、エージェントファイル、Skills、MCP 設定を一括で棚卸しする Python アプリです。

## Run

```bash
python3 server.py
```

Open:

```text
http://127.0.0.1:8766
```

## CLI Export

```bash
python3 inventory_scanner.py > report.json
python3 inventory_scanner.py --markdown > report.md
python3 inventory_scanner.py --html > report.html
```

## What It Scans

- `~/.codex`
- `~/.claude`
- `~/.agents`
- current workspace files such as `AGENTS.md`, `CLAUDE.md`, `.mcp.json`
- installed Skills with `SKILL.md`
- MCP server definitions in JSON/TOML-style config files
- CLI versions for `codex` and `claude`
- selected environment variables

## Safety

The scanner masks common secret fields and token-like values before showing previews or exporting reports. It is still a local diagnostic tool, so review exported files before sharing them outside your machine.

Do not commit generated inventory reports to a public repository unless you have reviewed them manually. Reports can include local paths, installed tools, private workspace names, and masked snippets of configuration files.
