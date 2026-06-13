from __future__ import annotations

import argparse
import json
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

    def send_json(self, payload) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_bytes(body, "application/json; charset=utf-8")

    def send_bytes(self, body: bytes, content_type: str) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


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
