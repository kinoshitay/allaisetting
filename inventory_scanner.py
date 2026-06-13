from __future__ import annotations

import fnmatch
import html
import json
import os
import platform
import re
import socket
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MAX_PREVIEW_CHARS = 16_000
MAX_SEARCH_DEPTH = 5
MAX_FILE_BYTES = 512_000

SENSITIVE_KEY_RE = re.compile(
    r"(api[_-]?key|token|secret|password|passwd|pwd|cookie|session|credential|private[_-]?key|authorization)",
    re.IGNORECASE,
)
SECRET_VALUE_PATTERNS = [
    (re.compile(r"sk-[A-Za-z0-9_\-]{16,}"), False),
    (re.compile(r"xox[baprs]-[A-Za-z0-9\-]{12,}"), False),
    (re.compile(r"(?:ghp|github_pat)_[A-Za-z0-9_]{20,}"), False),
    (re.compile(r"(Bearer\s+)[A-Za-z0-9._\-]{16,}", re.IGNORECASE), True),
    (re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"), False),
]

CONTEXT_FILENAMES = [
    "AGENTS.md",
    "CLAUDE.md",
    ".mcp.json",
    "settings.json",
    "config.toml",
    "config.json",
]

IMPORTANT_ENV_ALLOWLIST = [
    "SHELL",
    "USER",
    "HOME",
    "PATH",
    "CODEX_HOME",
    "CLAUDE_CONFIG_DIR",
    "OPENAI_MODEL",
    "ANTHROPIC_MODEL",
    "EDITOR",
    "LANG",
    "LC_ALL",
]

KNOWN_GITHUB_REPOS = {
    "claude-plugins-official": "https://github.com/anthropics/claude-plugins-official",
    "freee-mcp-marketplace": "https://github.com/freee/freee-mcp",
    "freee-mcp": "https://github.com/freee/freee-mcp",
}

GITHUB_URL_RE = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[^\s\"'<>)]*)?")
GITHUB_REPO_RE = re.compile(r"\b([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)\b")


@dataclass
class ScanOptions:
    workspace: Path
    include_previews: bool = True
    include_env: bool = True


def mask_text(text: str) -> str:
    masked_lines: list[str] = []
    for line in text.splitlines():
        key_match = re.match(r'\s*["\']?([^"\'=:]+)["\']?\s*[:=]', line)
        if key_match and SENSITIVE_KEY_RE.search(key_match.group(1)):
            key = key_match.group(1).strip()
            masked_lines.append(f"{key}: [REDACTED]")
            continue
        masked = line
        for pattern, preserve_prefix in SECRET_VALUE_PATTERNS:
            masked = pattern.sub(lambda m: (m.group(1) if preserve_prefix else "") + "[REDACTED]", masked)
        masked_lines.append(masked)
    return "\n".join(masked_lines)


def safe_read_text(path: Path) -> tuple[str | None, str | None]:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None, f"Skipped: larger than {MAX_FILE_BYTES} bytes"
        raw = path.read_bytes()
        text = raw.decode("utf-8", errors="replace")
        if len(text) > MAX_PREVIEW_CHARS:
            text = text[:MAX_PREVIEW_CHARS] + "\n...[truncated]"
        return mask_text(text), None
    except OSError as exc:
        return None, f"Read failed: {exc}"


def unique_strings(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def github_links_from_text(text: str | None) -> list[str]:
    if not text:
        return []
    links = []
    for match in GITHUB_URL_RE.finditer(text):
        url = match.group(0).rstrip(".,`")
        if "github.com/org/repo" in url or "github.com/OWNER/REPO" in url:
            continue
        links.append(url)
    for repo in GITHUB_REPO_RE.findall(text):
        owner, name = repo.split("/", 1)
        if "." in owner or "." in name:
            continue
        if owner.lower() in {"http:", "https:"}:
            continue
        if repo in {"path/to", "users/repo", "org/repo", "OWNER/REPO"}:
            continue
        if owner in {"anthropics", "freee", "oraios", "upstash"}:
            links.append(f"https://github.com/{repo}")
    return unique_strings(links)


def github_links_from_path(path: Path | str) -> list[str]:
    text = str(path)
    links: list[str] = []
    for marker, repo_url in KNOWN_GITHUB_REPOS.items():
        if marker in text:
            links.append(repo_url)
            plugin_match = re.search(rf"{re.escape(marker)}/(external_plugins|plugins)/([^/]+)", text)
            if plugin_match:
                links.append(f"{repo_url}/tree/main/{plugin_match.group(1)}/{plugin_match.group(2)}")
    return unique_strings(links)


def public_github_links(path: Path | str, text: str | None = None) -> list[str]:
    return unique_strings(github_links_from_path(path) + github_links_from_text(text))


def summarize_skill_japanese(name: str, source: str, description: str) -> str:
    if source == "Codex plugin cache":
        base = "Codex プラグインに同梱された Skill です。特定ツールを使う条件、手順、注意点をエージェントに教えます。"
    elif source == "Claude Code plugin cache":
        base = "Claude Code のインストール済みプラグインに同梱された Skill です。Claude Code が専門作業を実行するための手順や判断基準です。"
    elif source == "Claude Code marketplace":
        base = "Claude Code の marketplace 由来の Skill です。インストール候補やプラグイン提供の作業手順として参照できます。"
    elif source == "Agents shared skills":
        base = "Claude Code / Codex など複数エージェントで共有する Skill です。共通ワークフローを同じ作法で実行するための定義です。"
    elif source == "Claude":
        base = "Claude 側にインストールされた Skill です。Claude Code が専門作業を進めるためのローカル手順書です。"
    else:
        base = "Codex 側にインストールされた Skill です。作業分野ごとの判断基準や実行手順を追加します。"
    if description:
        return f"{base} 元説明: {description[:180]}"
    return f"{base} `{name}` という名前の作業能力として検出されました。"


def summarize_mcp_japanese(server_name: str, source: str) -> str:
    transport = "TOML 設定" if source == "toml" else "JSON 設定"
    return f"`{server_name}` をエージェントの外部ツールとして接続する MCP 設定です。{transport}から検出され、API やローカルコマンドを呼び出せるようにします。"


def summarize_context_file_japanese(category: str) -> str:
    if category == "agent/context":
        return "エージェントへの常設指示ファイルです。この環境での作業方針、コマンド、注意点を Claude Code / Codex に伝えます。"
    if category == "mcp":
        return "MCP サーバーの接続設定ファイルです。外部サービスやローカルツールをエージェントから使えるようにします。"
    if category == "settings":
        return "Claude Code / Codex / プラグインの動作設定です。有効なプラグイン、MCP、承認モードなどの意味があります。"
    return "この環境を理解するための補助コンテキストです。エージェントが作業時に参照する可能性があります。"


def command_version(command: str) -> dict[str, str]:
    try:
        result = subprocess.run(
            [command, "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
        )
        value = (result.stdout or result.stderr).strip()
        return {"command": command, "version": value or "installed, no version output"}
    except FileNotFoundError:
        return {"command": command, "version": "not found"}
    except Exception as exc:
        return {"command": command, "version": f"error: {exc}"}


def path_meta(path: Path) -> dict[str, Any]:
    try:
        stat = path.stat()
        return {
            "path": str(path),
            "exists": True,
            "type": "directory" if path.is_dir() else "file",
            "size": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
        }
    except OSError:
        return {"path": str(path), "exists": False}


def iter_limited_files(root: Path, patterns: list[str]) -> list[Path]:
    found: list[Path] = []
    if not root.exists():
        return found
    root = root.resolve()
    for current, dirnames, filenames in os.walk(root):
        current_path = Path(current)
        depth = len(current_path.relative_to(root).parts)
        dirnames[:] = [
            d
            for d in dirnames
            if not d.startswith(".git")
            and d not in {"node_modules", "__pycache__", ".venv", "venv", "Library", "Caches"}
            and depth < MAX_SEARCH_DEPTH
        ]
        for filename in filenames:
            if any(fnmatch.fnmatch(filename, pattern) for pattern in patterns):
                found.append(current_path / filename)
    return sorted(set(found))


def context_roots(workspace: Path, home: Path) -> list[Path]:
    roots = [
        workspace,
        home / ".codex",
        home / ".claude",
        home / ".agents",
        home / ".config" / "codex",
        home / ".config" / "claude",
    ]
    return [root for root in roots if root.exists()]


def scan_context_files(options: ScanOptions, home: Path) -> list[dict[str, Any]]:
    files: list[Path] = []
    for root in context_roots(options.workspace, home):
        if root.is_file():
            files.append(root)
        else:
            files.extend(iter_limited_files(root, CONTEXT_FILENAMES))
            for dirname in [".codex", ".claude"]:
                candidate = root / dirname
                if candidate.exists():
                    files.extend(iter_limited_files(candidate, CONTEXT_FILENAMES))
    items: list[dict[str, Any]] = []
    for path in sorted(set(files)):
        item = path_meta(path)
        item["category"] = classify_context_file(path)
        item["meaning_ja"] = summarize_context_file_japanese(item["category"])
        if options.include_previews and path.is_file():
            preview, error = safe_read_text(path)
            item["preview"] = preview
            item["error"] = error
            item["github_urls"] = public_github_links(path, preview)
        else:
            item["github_urls"] = public_github_links(path)
        items.append(item)
    return items


def classify_context_file(path: Path) -> str:
    name = path.name.lower()
    if name in {"agents.md", "claude.md"}:
        return "agent/context"
    if "mcp" in name:
        return "mcp"
    if name in {"settings.json", "config.toml", "config.json"}:
        return "settings"
    return "context"


def scan_skills(home: Path) -> list[dict[str, Any]]:
    roots = [
        home / ".codex" / "skills",
        home / ".claude" / "skills",
        home / ".agents" / "skills",
        home / ".codex" / "plugins" / "cache",
        home / ".claude" / "plugins" / "cache",
        home / ".claude" / "plugins" / "marketplaces",
    ]
    skill_files: list[Path] = []
    for root in roots:
        skill_files.extend(iter_limited_files(root, ["SKILL.md"]))
    skills: list[dict[str, Any]] = []
    for skill_file in sorted(set(skill_files)):
        content, error = safe_read_text(skill_file)
        title = skill_file.parent.name
        description = ""
        if content:
            match = re.search(r"^description:\s*(.+)$", content, re.MULTILINE)
            if match:
                description = match.group(1).strip()
            elif content.startswith("---"):
                description = content.split("---", 2)[1].strip().splitlines()[0] if "---" in content[3:] else ""
        skills.append(
            {
                "name": title,
                "path": str(skill_file),
                "source": skill_source(skill_file, home),
                "description": description,
                "meaning_ja": summarize_skill_japanese(title, skill_source(skill_file, home), description),
                "github_urls": public_github_links(skill_file, description),
                "error": error,
            }
        )
    return skills


def skill_source(path: Path, home: Path) -> str:
    as_text = str(path)
    if f"{home}/.codex/plugins/cache" in as_text:
        return "Codex plugin cache"
    if f"{home}/.claude/plugins/cache" in as_text:
        return "Claude Code plugin cache"
    if f"{home}/.claude/plugins/marketplaces" in as_text:
        return "Claude Code marketplace"
    if f"{home}/.agents/skills" in as_text:
        return "Agents shared skills"
    if f"{home}/.claude" in as_text:
        return "Claude"
    return "Codex"


def extract_mcp_servers_from_text(text: str) -> list[dict[str, str]]:
    servers: dict[str, dict[str, str]] = {}
    for match in re.finditer(r"\[mcp_servers\.([^\]]+)\]", text):
        name = match.group(1).strip('"')
        servers[name] = {"name": name, "source": "toml"}
    for match in re.finditer(r'"([^"]+)"\s*:\s*\{[^{}]*(?:"command"|"url")\s*:', text):
        name = match.group(1)
        if name not in {"mcpServers", "servers"}:
            servers[name] = {"name": name, "source": "json"}
    return list(servers.values())


def scan_mcp(context_files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for file_item in context_files:
        preview = file_item.get("preview")
        path = file_item.get("path", "")
        parse_text = preview
        if not parse_text and path:
            parse_text, _ = safe_read_text(Path(path))
        if not parse_text or ("mcp" not in path.lower() and "mcp" not in parse_text.lower()):
            continue
        servers = [
            {
                **server,
                "meaning_ja": summarize_mcp_japanese(server["name"], server.get("source", "")),
                "github_urls": public_github_links(path, parse_text),
            }
            for server in extract_mcp_servers_from_text(parse_text)
        ]
        items.append(
            {
                "path": path,
                "servers": servers,
                "preview": preview,
                "meaning_ja": summarize_context_file_japanese("mcp"),
                "github_urls": public_github_links(path, parse_text),
            }
        )
    return items


def scan_important_settings(options: ScanOptions, home: Path) -> dict[str, Any]:
    settings: dict[str, Any] = {
        "device": {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": sys.version.split()[0],
            "cwd": str(options.workspace),
            "home": str(home),
        },
        "cli_versions": [command_version("codex"), command_version("claude")],
        "known_paths": [
            path_meta(home / ".codex"),
            path_meta(home / ".claude"),
            path_meta(home / ".agents"),
            path_meta(options.workspace / "AGENTS.md"),
            path_meta(options.workspace / "CLAUDE.md"),
        ],
    }
    if options.include_env:
        settings["environment"] = {
            key: mask_text(os.environ.get(key, "")) for key in IMPORTANT_ENV_ALLOWLIST if key in os.environ
        }
    return settings


def run_scan(workspace: str | Path | None = None, include_previews: bool = True) -> dict[str, Any]:
    home = Path.home()
    ws = Path(workspace or os.getcwd()).expanduser().resolve()
    options = ScanOptions(workspace=ws, include_previews=include_previews)
    context_files = scan_context_files(options, home)
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "settings": scan_important_settings(options, home),
        "context_files": context_files,
        "skills": scan_skills(home),
        "mcp": scan_mcp(context_files),
    }
    report["summary"] = {
        "context_files": len(report["context_files"]),
        "skills": len(report["skills"]),
        "mcp_config_files": len(report["mcp"]),
        "mcp_servers": sum(len(item.get("servers", [])) for item in report["mcp"]),
    }
    return report


def report_to_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# All AI Setting Environment Inventory",
        "",
        f"- Generated: `{report.get('generated_at')}`",
        f"- Host: `{report['settings']['device'].get('hostname')}`",
        f"- Workspace: `{report['settings']['device'].get('cwd')}`",
        "",
        "## Summary",
    ]
    for key, value in report.get("summary", {}).items():
        lines.append(f"- {key}: {value}")
    lines.extend(["", "## CLI Versions"])
    for item in report["settings"].get("cli_versions", []):
        lines.append(f"- `{item['command']}`: {item['version']}")
    lines.extend(["", "## Skills"])
    for skill in report.get("skills", []):
        desc = f" - {skill['description']}" if skill.get("description") else ""
        lines.append(f"- `{skill['name']}` ({skill['source']}): `{skill['path']}`{desc}")
        if skill.get("meaning_ja"):
            lines.append(f"  - 意味: {skill['meaning_ja']}")
        for url in skill.get("github_urls", []):
            lines.append(f"  - GitHub: {url}")
    lines.extend(["", "## MCP"])
    for item in report.get("mcp", []):
        server_names = ", ".join(server["name"] for server in item.get("servers", [])) or "No server names detected"
        lines.append(f"- `{item['path']}`: {server_names}")
        if item.get("meaning_ja"):
            lines.append(f"  - 意味: {item['meaning_ja']}")
        for url in item.get("github_urls", []):
            lines.append(f"  - GitHub: {url}")
        for server in item.get("servers", []):
            if server.get("meaning_ja"):
                lines.append(f"  - `{server['name']}` の意味: {server['meaning_ja']}")
            for url in server.get("github_urls", []):
                lines.append(f"  - `{server['name']}` GitHub: {url}")
    lines.extend(["", "## Context And Agent Files"])
    for file_item in report.get("context_files", []):
        lines.append(f"### {file_item.get('path')}")
        lines.append(f"- Category: {file_item.get('category')}")
        if file_item.get("meaning_ja"):
            lines.append(f"- 意味: {file_item['meaning_ja']}")
        for url in file_item.get("github_urls", []):
            lines.append(f"- GitHub: {url}")
        if file_item.get("preview"):
            lines.append("")
            lines.append("```")
            lines.append(file_item["preview"])
            lines.append("```")
        if file_item.get("error"):
            lines.append(f"- Error: {file_item['error']}")
        lines.append("")
    return "\n".join(lines)


def report_to_html(report: dict[str, Any]) -> str:
    markdown = report_to_markdown(report)
    escaped = html.escape(markdown)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>All AI Setting Environment Inventory</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 32px; line-height: 1.5; }}
    pre {{ white-space: pre-wrap; background: #f5f5f5; padding: 16px; border-radius: 8px; }}
  </style>
</head>
<body><pre>{escaped}</pre></body>
</html>"""


def main() -> int:
    report = run_scan()
    if len(sys.argv) > 1 and sys.argv[1] == "--markdown":
        print(report_to_markdown(report))
    elif len(sys.argv) > 1 and sys.argv[1] == "--html":
        print(report_to_html(report))
    else:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
