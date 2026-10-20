"""
Archive extraction for .zip and .rar, plus source-file collection.

.zip  -> stdlib zipfile
.rar  -> WinRAR's UnRAR.exe, or the `rarfile` package with an unrar backend
All extraction is guarded against path traversal ("zip slip").
"""

import os
import re
import shutil
import zipfile
import tempfile

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
MAX_ARCHIVE_MEMBERS = 20000
MAX_EXTRACTED_BYTES = 512 * 1024 * 1024

UNRAR_CANDIDATES = [
    r"C:\Program Files\WinRAR\UnRAR.exe",
    r"C:\Program Files (x86)\WinRAR\UnRAR.exe",
]

# Characters Windows refuses in a path component, and the control range. A zip
# built on macOS or Linux can legally carry them, so extracting under the
# member's own name fails the whole archive rather than one file.
_ILLEGAL_CHARS = re.compile(r'[<>:"|?*\x00-\x1f]')
# Names the reserved device files answer to, with or without an extension.
_RESERVED_STEMS = {"con", "prn", "aux", "nul"} | {
    "%s%d" % (p, i) for i in range(1, 10) for p in ("com", "lpt")
}


def _find_unrar():
    exe = shutil.which("unrar") or shutil.which("UnRAR")
    if exe:
        return exe
    for c in UNRAR_CANDIDATES:
        if os.path.isfile(c):
            return c
    return None


def _safe_disk_name(name):
    """Make one path component writable, leaving it recognisable."""
    clean = _ILLEGAL_CHARS.sub("_", name)
    stem, ext = os.path.splitext(clean)
    if stem.lower() in _RESERVED_STEMS:
        clean = stem + "_" + ext
    # Windows also drops trailing dots and spaces, which would collide with a
    # sibling that has none.
    clean = clean.rstrip(". ")
    return clean or "_"


def _safe_target(dest, name):
    """Resolve an archive member path inside dest, rejecting traversal."""
    name = name.replace("\\", "/").lstrip("/")
    parts = []
    for piece in name.split("/"):
        # A reserved `..` is kept on purpose: normpath collapses it and the
        # prefix check below is what rejects an escape.
        if piece == "..":
            parts.append(piece)
            continue
        if piece in ("", "."):
            continue
        parts.append(_safe_disk_name(piece))
    if not parts:
        raise ValueError("ruta vacía en el archivo: %s" % name)
    target = os.path.normpath(os.path.join(dest, *parts))
    if not target.startswith(os.path.normpath(dest) + os.sep) and target != os.path.normpath(dest):
        raise ValueError("ruta insegura en el archivo: %s" % name)
    return target


def _write_member(reader, info, target, remaining_bytes):
    """Extract one member, leaving a sanitised name on disk.

    The name is rewritten (see `_safe_disk_name`) so a path that is legal where
    the archive was built still lands on Windows; the content is untouched,
    which is what gets analysed. One member that still cannot be written is
    skipped rather than allowed to fail the whole archive.
    """
    if getattr(info, "file_size", 0) > remaining_bytes:
        raise ValueError("El archivo comprimido supera el límite de extracción de 512 MB.")
    os.makedirs(os.path.dirname(target), exist_ok=True)
    copied = 0
    try:
        with reader(info) as src, open(target, "wb") as dst:
            while True:
                chunk = src.read(1 << 16)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > remaining_bytes:
                    raise ValueError("El archivo comprimido supera el límite de extracción de 512 MB.")
                dst.write(chunk)
    except OSError:
        return 0
    return copied


def extract_zip(archive, dest):
    with zipfile.ZipFile(archive) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_ARCHIVE_MEMBERS:
            raise ValueError("El archivo comprimido tiene más de 20000 elementos.")
        declared_size = sum(max(0, info.file_size) for info in infos if not info.is_dir())
        if declared_size > MAX_EXTRACTED_BYTES:
            raise ValueError("El archivo comprimido supera el límite de extracción de 512 MB.")
        extracted = 0
        for info in infos:
            if info.is_dir():
                continue
            extracted += _write_member(zf.open, info, _safe_target(dest, info.filename),
                                       MAX_EXTRACTED_BYTES - extracted)


def extract_rar(archive, dest):
    unrar = _find_unrar()
    try:
        import rarfile
    except ImportError:
        raise RuntimeError(
            "No se puede extraer .rar: instala `rarfile` y un backend como "
            "WinRAR/UnRAR o unrar en el PATH.")
    if unrar:
        rarfile.UNRAR_TOOL = unrar
    with rarfile.RarFile(archive) as rf:
        infos = rf.infolist()
        if len(infos) > MAX_ARCHIVE_MEMBERS:
            raise ValueError("El archivo comprimido tiene más de 20000 elementos.")
        declared_size = sum(max(0, info.file_size) for info in infos if not info.isdir())
        if declared_size > MAX_EXTRACTED_BYTES:
            raise ValueError("El archivo comprimido supera el límite de extracción de 512 MB.")
        extracted = 0
        for info in infos:
            if info.isdir():
                continue
            extracted += _write_member(rf.open, info, _safe_target(dest, info.filename),
                                       MAX_EXTRACTED_BYTES - extracted)


def extract(archive_path, filename):
    """Extract archive into a fresh temp dir. Returns that dir."""
    dest = tempfile.mkdtemp(prefix="aicode_")
    try:
        lower = filename.lower()
        if lower.endswith(".zip"):
            extract_zip(archive_path, dest)
        elif lower.endswith(".rar"):
            extract_rar(archive_path, dest)
        else:
            raise ValueError("Tipo de archivo no soportado: %s (usa .zip o .rar)" % filename)
    except Exception:
        cleanup(dest)
        raise
    return dest


def _is_ignored(relpath):
    parts = relpath.replace("\\", "/").split("/")
    return any(p in IGNORED_DIRS for p in parts[:-1])


def _decode(data):
    if b"\x00" in data:
        return None
    for enc in ("utf-8-sig", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return None


def collect_sources(root):
    """Walk extracted tree. Returns ([(relpath, text)], truncated).

    `truncated` says the walk stopped at MAX_FILES with files still to read,
    so the report can admit it instead of looking complete.
    """
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for fn in filenames:
            if len(files) >= MAX_FILES:
                return files, True
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
    return files, False


def cleanup(path):
    shutil.rmtree(path, ignore_errors=True)
