from __future__ import annotations

import argparse
import json
import shutil
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from inventory_scanner import report_to_html, report_to_markdown, run_scan


ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"


class InventoryHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC), **kwargs)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self.path = "/index.html"
            return super().do_GET()
        if parsed.path == "/api/scan":
            return self.handle_scan(parsed.query)
        if parsed.path == "/export.json":
            return self.handle_export("json")
        if parsed.path == "/export.md":
            return self.handle_export("markdown")
        if parsed.path == "/export.html":
            return self.handle_export("html")
        return super().do_GET()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/quarantine":
            return self.handle_quarantine()
        if parsed.path == "/api/share-skill":
            return self.handle_share_skill()
        self.send_json({"ok": False, "error": "Not found"}, status=HTTPStatus.NOT_FOUND)

    def handle_scan(self, query: str) -> None:
        params = parse_qs(query)
        include_previews = params.get("previews", ["1"])[0] != "0"
        report = run_scan(ROOT, include_previews=include_previews)
        self.send_json(report)

    def handle_export(self, export_type: str) -> None:
        report = run_scan(ROOT, include_previews=True)
        if export_type == "json":
            body = json.dumps(report, ensure_ascii=False, indent=2)
            self.send_bytes(body.encode("utf-8"), "application/json; charset=utf-8")
        elif export_type == "markdown":
            body = report_to_markdown(report)
            self.send_bytes(body.encode("utf-8"), "text/markdown; charset=utf-8")
        else:
            body = report_to_html(report)
            self.send_bytes(body.encode("utf-8"), "text/html; charset=utf-8")

    def handle_quarantine(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            requested_path = Path(str(payload.get("path", ""))).expanduser().resolve(strict=True)
            candidates = {
                Path(item["path"]).expanduser().resolve(strict=True)
                for item in run_scan(ROOT, include_previews=False).get("cleanup_candidates", [])
            }
            if requested_path not in candidates:
                return self.send_json(
                    {"ok": False, "error": "This file is not an allowed cleanup candidate."},
                    status=HTTPStatus.BAD_REQUEST,
                )
            destination = quarantine_destination(requested_path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(requested_path), str(destination))
            self.send_json({"ok": True, "moved_to": str(destination)})
        except Exception as exc:
            self.send_json({"ok": False, "error": str(exc)}, status=HTTPStatus.BAD_REQUEST)

    def handle_share_skill(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            requested_path = Path(str(payload.get("path", ""))).expanduser().resolve(strict=True)
            skills = run_scan(ROOT, include_previews=False).get("skills", [])
            allowed = {
                Path(item["path"]).expanduser().resolve(strict=True): item
                for item in skills
                if item.get("share_allowed")
            }
            skill = allowed.get(requested_path)
            if not skill:
                return self.send_json(
                    {"ok": False, "error": "This skill is not an allowed share candidate."},
                    status=HTTPStatus.BAD_REQUEST,
                )
            source_dir = requested_path.parent
            destination = Path(skill["share_target"]).expanduser()
            shared_root = Path.home() / ".agents" / "skills"
            if shared_root.resolve() not in [destination.resolve().parent, *destination.resolve().parents]:
                return self.send_json(
                    {"ok": False, "error": "Invalid shared skill destination."},
                    status=HTTPStatus.BAD_REQUEST,
                )
            if destination.exists():
                return self.send_json(
                    {"ok": False, "error": "Shared skill already exists."},
                    status=HTTPStatus.BAD_REQUEST,
                )
            shared_root.mkdir(parents=True, exist_ok=True)
            shutil.copytree(source_dir, destination, symlinks=True)
            self.send_json({"ok": True, "copied_to": str(destination)})
        except Exception as exc:
            self.send_json({"ok": False, "error": str(exc)}, status=HTTPStatus.BAD_REQUEST)

    def send_json(self, payload, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_bytes(body, "application/json; charset=utf-8", status=status)

    def send_bytes(self, body: bytes, content_type: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def quarantine_destination(path: Path) -> Path:
    stamp = path.stat().st_mtime_ns
    trash_root = Path.home() / ".all-ai-setting-trash"
    safe_parts = [part for part in path.parts if part not in {"/", ""}]
    return trash_root / f"{stamp}" / Path(*safe_parts)


def main() -> int:
    parser = argparse.ArgumentParser(description="Local AI agent environment inventory app")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), InventoryHandler)
    print(f"Inventory app running at http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping inventory app")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
