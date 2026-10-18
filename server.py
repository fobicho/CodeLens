"""
CodeLens - local web server.

    python server.py [--port 8000] [--host 127.0.0.1] [--no-browser]

Serves the UI at / and accepts an archive upload at POST /analyze.
The browser posts the raw file bytes and passes the original name as
?filename=<name>; this avoids multipart parsing entirely.

An analysis is handed to the report page rather than rendered under the
landing page: POST /analyze keeps the result under a short token and returns
that token, and GET /report?id=<token> serves it back to report.html. The
store is bounded and lives only in memory, so nothing is written to disk and
nothing survives a restart.
"""

import os
import sys
import json
import argparse
import mimetypes
import secrets
import tempfile
import threading
import webbrowser
from collections import OrderedDict
from urllib.parse import urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import detector
import audit
import extractor

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC_EXTS = {".png", ".svg", ".ico", ".webp", ".jpg", ".jpeg", ".gif",
               ".css", ".html", ".js", ".woff", ".woff2"}

# How many finished analyses to keep reachable. The flow is analyse, read the
# report, analyse again, so a handful covers reloads and a second tab without
# holding on to unbounded amounts of analysed source in memory.
REPORT_LIMIT = 4
REPORTS = OrderedDict()
REPORTS_LOCK = threading.Lock()

MAX_UPLOAD_BYTES = 256 * 1024 * 1024


def stash_report(result):
    """Store a finished analysis and return the token that addresses it."""
    token = secrets.token_urlsafe(12)
    with REPORTS_LOCK:
        REPORTS[token] = result
        while len(REPORTS) > REPORT_LIMIT:
            REPORTS.popitem(last=False)
    return token


def fetch_report(token):
    """Return the stored analysis, or None if the token is unknown or evicted."""
    if not token:
        return None
    with REPORTS_LOCK:
        return REPORTS.get(token)


def analyze_archive_bytes(data, filename):

    suffix = ".rar" if filename.lower().endswith(".rar") else ".zip"
    fd, tmp = tempfile.mkstemp(suffix=suffix)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        root = extractor.extract(tmp, filename)
        try:
            files, truncated = extractor.collect_sources(root)
            if not files:
                return {"error": "No se encontraron archivos fuente en el archivo."}
            result = detector.analyze_project(files)
            result["audit"] = audit.build_audit(files)
            result["truncated"] = truncated
            result["max_files"] = extractor.MAX_FILES
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
    timeout = 30

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
        parsed = urlparse(self.path)
        # The report page reads its analysis back by token. Checked before the
        # static handler so the route cannot be shadowed by a file of that name.
        if parsed.path == "/report":
            token = (parse_qs(parsed.query).get("id", [""])[0] or "").strip()
            report = fetch_report(token)
            if report is None:
                self._json(404, {"error": "Informe no encontrado. Vuelve a analizar el archivo."})
            else:
                self._json(200, report)
            return
        rel = parsed.path.lstrip("/") or "index.html"
        # Resolve against the project root and refuse anything that escapes it,
        # so static assets can live in subdirectories without opening a
        # directory-traversal hole.
        full = os.path.realpath(os.path.join(HERE, rel.replace("\\", "/")))
        if full != HERE and not full.startswith(HERE + os.sep):
            self._send(404, "Not found", "text/plain; charset=utf-8")
            return
        ext = os.path.splitext(full)[1].lower()
        if ext not in STATIC_EXTS:
            self._send(404, "Not found", "text/plain; charset=utf-8")
            return
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
        if self.headers.get("X-CodeLens") != "1":
            self._json(403, {"error": "Petición no reconocida."})
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0
        if length <= 0:
            self._json(400, {"error": "Subida vacía."})
            return
        if length > MAX_UPLOAD_BYTES:
            self.close_connection = True
            self._json(413, {"error": "El archivo supera el límite de %d MB."
                                      % (MAX_UPLOAD_BYTES // (1024 * 1024))})
            return
        data = self.rfile.read(length)
        qs = parse_qs(urlparse(self.path).query)
        filename = (qs.get("filename", ["upload.zip"])[0]) or "upload.zip"
        if not filename.lower().endswith((".zip", ".rar")):
            self._json(400, {"error": "Sube un archivo .zip o .rar."})
            return
        try:
            result = analyze_archive_bytes(data, filename)
        except ValueError as exc:
            self._json(400, {"error": str(exc)})
            return
        except Exception as exc:  # noqa: BLE001 - surface a clean message to the UI
            self._json(500, {"error": "El análisis falló: %s" % exc})
            return
        if "error" in result:
            self._json(400, result)
            return
        # The landing page only needs a token to navigate with, plus enough to
        # reassure the reader while it hands off; the report page pulls the
        # whole analysis back by token. Keeping the response light also keeps
        # the file list out of the navigation payload.
        result["source_name"] = filename
        token = stash_report(result)
        self._json(200, {
            "report_id": token,
            "source_name": filename,
            "verdict": result.get("verdict"),
            "avg_score": result.get("avg_score"),
            "total_files": result.get("total_files"),
        })

    def _json(self, code, obj):
        self._send(code, json.dumps(obj), "application/json; charset=utf-8")


def main():
    ap = argparse.ArgumentParser(description="Servidor local de CodeLens")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    url = "http://%s:%d/" % (args.host, args.port)
    print("CodeLens en ejecución en %s" % url)
    print("Pulsa Ctrl+C para detener.")
    if not args.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nCerrando.")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
