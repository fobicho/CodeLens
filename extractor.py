"""
Archive extraction for .zip and .rar, plus source-file collection.

.zip  -> stdlib zipfile
.rar  -> WinRAR's UnRAR.exe, or the `rarfile` package with an unrar backend
All extraction is guarded against path traversal ("zip slip").
"""

import os
import shutil
import zipfile
import tempfile
import subprocess

SOURCE_EXTS = {
    "js", "mjs", "cjs", "jsx", "ts", "tsx", "mts", "cts", "py", "pyw", "php",
    "rb", "java", "kt", "kts", "cs", "go", "rs", "swift", "scala", "c", "h",
    "cpp", "cc", "cxx", "hpp", "m", "mm", "html", "htm", "vue", "svelte",
    "css", "scss", "less", "sass", "json", "yaml", "yml", "toml", "xml",
    "sql", "sh", "bash", "ps1", "dart", "r", "pl", "lua", "ex", "exs",
}

IGNORED_DIRS = {
    "node_modules", ".git", ".hg", ".svn", "dist", "build", "out", "output",
    "vendor", "__pycache__", ".venv", "venv", "env", ".env", "coverage",
    ".next", ".nuxt", ".cache", "target", ".idea", ".vscode", "bin", "obj",
    "packages", "site-packages", ".mypy_cache", ".pytest_cache", ".tox",
    "bower_components", ".gradle", ".terraform", "Pods", "DerivedData",
}

MAX_FILE_BYTES = 1_500_000
MAX_FILES = 8000

UNRAR_CANDIDATES = [
    r"C:\Program Files\WinRAR\UnRAR.exe",
    r"C:\Program Files (x86)\WinRAR\UnRAR.exe",
]


def _find_unrar():
    exe = shutil.which("unrar") or shutil.which("UnRAR")
    if exe:
        return exe
    for c in UNRAR_CANDIDATES:
        if os.path.isfile(c):
            return c
    return None


def _safe_target(dest, name):
    """Resolve an archive member path inside dest, rejecting traversal."""
    name = name.replace("\\", "/").lstrip("/")
    target = os.path.normpath(os.path.join(dest, name))
    if not target.startswith(os.path.normpath(dest) + os.sep) and target != os.path.normpath(dest):
        raise ValueError("unsafe path in archive: %s" % name)
    return target


def extract_zip(archive, dest):
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            target = _safe_target(dest, info.filename)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst, length=1 << 16)


def extract_rar(archive, dest):
    unrar = _find_unrar()
    if unrar:
        cmd = [unrar, "x", "-o+", "-inul", "-y", archive, dest + os.sep]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode in (0, 1):  # 1 = warnings
            return
        raise RuntimeError("unrar failed (%d): %s" % (proc.returncode, proc.stderr.strip()))
    try:
        import rarfile
    except ImportError:
        raise RuntimeError(
            "Cannot extract .rar: install WinRAR (provides UnRAR.exe) or "
            "`pip install rarfile` with an unrar backend on PATH.")
    with rarfile.RarFile(archive) as rf:
        for info in rf.infolist():
            if info.isdir():
                continue
            target = _safe_target(dest, info.filename)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with rf.open(info) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst, length=1 << 16)


def extract(archive_path, filename):
    """Extract archive into a fresh temp dir. Returns that dir."""
    dest = tempfile.mkdtemp(prefix="aicode_")
    lower = filename.lower()
    if lower.endswith(".zip"):
        extract_zip(archive_path, dest)
    elif lower.endswith(".rar"):
        extract_rar(archive_path, dest)
    else:
        raise ValueError("Unsupported archive type: %s (use .zip or .rar)" % filename)
    return dest


def _is_ignored(relpath):
    parts = relpath.replace("\\", "/").split("/")
    return any(p in IGNORED_DIRS for p in parts[:-1])


def _decode(data):
    for enc in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            text = data.decode(enc)
            if enc == "latin-1" or "\x00" not in text:
                return text
        except UnicodeDecodeError:
            continue
    return None


def collect_sources(root):
    """Walk extracted tree, returning [(relpath, text)] for source files."""
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for fn in filenames:
            if len(files) >= MAX_FILES:
                return files
            ext = fn.rsplit(".", 1)[-1].lower() if "." in fn else ""
            if ext not in SOURCE_EXTS:
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace("\\", "/")
            if _is_ignored(rel):
                continue
            try:
                if os.path.getsize(full) > MAX_FILE_BYTES:
                    continue
                with open(full, "rb") as fh:
                    data = fh.read()
            except OSError:
                continue
            text = _decode(data)
            if text is None:
                continue
            files.append((rel, text))
    return files


def cleanup(path):
    shutil.rmtree(path, ignore_errors=True)
