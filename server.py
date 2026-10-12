"""
CodeLens - local web server.

    python server.py [--port 8000] [--host 127.0.0.1] [--no-browser]

Serves the UI at / and accepts an archive upload at POST /analyze.
The browser posts the raw file bytes and passes the original name as
?filename=<name>; this avoids multipart parsing entirely.
"""

import os
import sys
import json
import argparse
import mimetypes
import tempfile
import threading
import webbrowser
from urllib.parse import urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import detector
import audit
import extractor

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC_EXTS = {".png", ".svg", ".ico", ".webp", ".jpg", ".jpeg", ".gif"}


def analyze_archive_bytes(data, filename):
    suffix = ".rar" if filename.lower().endswith(".rar") else ".zip"
    fd, tmp = tempfile.mkstemp(suffix=suffix)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        root = extractor.extract(tmp, filename)
        try:
            files = extractor.collect_sources(root)
            if not files:
                return {"error": "No source files found in the archive."}
            result = detector.analyze_project(files)
            result["audit"] = audit.build_audit(files)
            return result
        finally:
            extractor.cleanup(root)
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


class Handler(BaseHTTPRequestHandler):
    server_version = "CodeLens/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, code, body, content_type):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        rel = urlparse(self.path).path.lstrip("/") or "index.html"
        if "/" in rel or "\\" in rel or rel.startswith("."):
            self._send(404, "Not found", "text/plain; charset=utf-8")
            return
        ext = os.path.splitext(rel)[1].lower()
        if rel != "index.html" and ext not in STATIC_EXTS:
            self._send(404, "Not found", "text/plain; charset=utf-8")
            return
        full = os.path.join(HERE, rel)
        if not os.path.isfile(full):
            self._send(404, "Not found", "text/plain; charset=utf-8")
            return
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "image/svg+xml"):
            ctype += "; charset=utf-8"
        try:
            with open(full, "rb") as fh:
                self._send(200, fh.read(), ctype)
        except OSError:
            self._send(500, "Read error", "text/plain; charset=utf-8")

    def do_POST(self):
        path = urlparse(self.path).path
        if path != "/analyze":
            self._send(404, "Not found", "text/plain; charset=utf-8")
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0
        if length <= 0:
            self._json(400, {"error": "Empty upload."})
            return
        data = self.rfile.read(length)
        qs = parse_qs(urlparse(self.path).query)
        filename = (qs.get("filename", ["upload.zip"])[0]) or "upload.zip"
        if not filename.lower().endswith((".zip", ".rar")):
            self._json(400, {"error": "Please upload a .zip or .rar file."})
            return
        try:
            result = analyze_archive_bytes(data, filename)
        except ValueError as exc:
            self._json(400, {"error": str(exc)})
            return
        except Exception as exc:  # noqa: BLE001 - surface a clean message to the UI
            self._json(500, {"error": "Analysis failed: %s" % exc})
            return
        if "error" in result:
            self._json(400, result)
        else:
            self._json(200, result)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj), "application/json; charset=utf-8")


def main():
    ap = argparse.ArgumentParser(description="AI Code Detector local server")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    url = "http://%s:%d/" % (args.host, args.port)
    print("CodeLens running at %s" % url)
    print("Press Ctrl+C to stop.")
    if not args.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
