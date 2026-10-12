"""
CodeLens - analysis engine.

Computes seven per-file signals (0-100, higher = more AI-like) and aggregates
them into a final score, mirroring the signal set reverse-engineered from the
original "code-auditor" service:

    Generic variable naming, Code density, Comment ratio & trivial comments,
    Formatting consistency, Error handling pattern, Structure, Modern feature use
"""

import re
import statistics

# --------------------------------------------------------------------------
# Language handling
# --------------------------------------------------------------------------

LANG_BY_EXT = {
    "js": "javascript", "mjs": "javascript", "cjs": "javascript", "jsx": "javascript",
    "ts": "typescript", "tsx": "typescript", "mts": "typescript", "cts": "typescript",
    "py": "python", "pyw": "python",
    "php": "php", "rb": "ruby", "java": "java", "kt": "kotlin", "kts": "kotlin",
    "cs": "csharp", "go": "go", "rs": "rust", "swift": "swift", "scala": "scala",
    "c": "c", "h": "c", "cpp": "cpp", "cc": "cpp", "cxx": "cpp", "hpp": "cpp",
    "m": "objc", "mm": "objc",
    "html": "html", "htm": "html", "vue": "vue", "svelte": "svelte",
    "css": "css", "scss": "scss", "less": "less", "sass": "sass",
    "json": "json", "yaml": "yaml", "yml": "yaml", "toml": "toml",
    "xml": "xml", "sql": "sql", "sh": "shell", "bash": "shell", "ps1": "powershell",
    "dart": "dart", "r": "r", "pl": "perl", "lua": "lua", "ex": "elixir", "exs": "elixir",
}

LANG_TAG = {
    "javascript": "JS", "typescript": "TS", "python": "PY", "php": "PHP",
    "ruby": "RB", "java": "JAVA", "kotlin": "KT", "csharp": "C#", "go": "GO",
    "rust": "RS", "swift": "SWIFT", "scala": "SCALA", "c": "C", "cpp": "C++",
    "html": "HTML", "vue": "VUE", "svelte": "SVELTE", "css": "CSS", "scss": "SCSS",
    "less": "LESS", "sass": "SASS", "json": "JSON", "yaml": "YAML", "toml": "TOML",
    "xml": "XML", "sql": "SQL", "shell": "SH", "powershell": "PS1", "dart": "DART",
    "r": "R", "perl": "PL", "lua": "LUA", "elixir": "EX", "objc": "OBJC", "unknown": "??",
}

LINE_COMMENT = {
    "javascript": ["//"], "typescript": ["//"], "python": ["#"], "php": ["//", "#"],
    "ruby": ["#"], "java": ["//"], "kotlin": ["//"], "csharp": ["//"], "go": ["//"],
    "rust": ["//"], "swift": ["//"], "scala": ["//"], "c": ["//"], "cpp": ["//"],
    "objc": ["//"], "css": [], "scss": [], "less": [], "sass": [], "sql": ["--"],
    "shell": ["#"], "powershell": ["#"], "dart": ["//"], "r": ["#"], "perl": ["#"],
    "lua": ["--"], "elixir": ["#"], "yaml": ["#"], "toml": ["#"], "json": [],
}

BLOCK_COMMENT = {
    "javascript": ("/*", "*/"), "typescript": ("/*", "*/"), "java": ("/*", "*/"),
    "kotlin": ("/*", "*/"), "csharp": ("/*", "*/"), "go": ("/*", "*/"), "rust": ("/*", "*/"),
    "swift": ("/*", "*/"), "scala": ("/*", "*/"), "c": ("/*", "*/"), "cpp": ("/*", "*/"),
    "objc": ("/*", "*/"), "css": ("/*", "*/"), "scss": ("/*", "*/"), "less": ("/*", "*/"),
    "sass": ("/*", "*/"), "dart": ("/*", "*/"), "php": ("/*", "*/"),
    "python": ('"""', '"""'), "html": ("<!--", "-->"), "xml": ("<!--", "-->"),
    "vue": ("<!--", "-->"), "svelte": ("<!--", "-->"), "sql": ("/*", "*/"),
}

GENERIC_NAMES = {
    "data", "result", "results", "res", "response", "resp", "value", "val",
    "item", "items", "temp", "tmp", "obj", "object", "arr", "array", "list",
    "str", "string", "num", "number", "count", "index", "idx", "key", "flag",
    "test", "foo", "bar", "baz", "info", "context", "ctx", "params", "props",
    "options", "opts", "config", "cfg", "handle", "handler", "callback", "cb",
    "process", "execute", "run", "main", "input", "output", "out", "err", "error",
    "element", "elem", "node", "container", "wrapper", "value1", "value2",
    "utils", "helper", "helpers", "manager", "service", "model", "entity",
    "payload", "body", "headers", "request", "req", "args", "arguments",
}

TRIVIAL_COMMENT_WORDS = {
    "import", "imports", "initialize", "init", "set up", "setup", "define",
    "declare", "create", "creates", "update", "updates", "handle", "handles",
    "return", "returns", "export", "exports", "get", "gets", "set", "sets",
    "todo", "fixme", "note", "example", "usage", "helper", "main", "entry",
    "constructor", "render", "component", "function", "check", "loop",
}

MODERN_FEATURES = {
    "javascript": [
        ("Arrow functions", r"=>"),
        ("Template literals", r"`"),
        ("Destructuring", r"\b(?:const|let|var)\s*[\[{]"),
        ("Async/Await", r"\b(?:async|await)\b"),
        ("Optional chaining", r"\?\."),
        ("Nullish coalescing", r"\?\?"),
        ("Spread/Rest", r"\.\.\."),
        ("const/let", r"\b(?:const|let)\b"),
        ("Promises", r"\bPromise\b|\.then\("),
        ("ES modules", r"\bimport\b[^\n]*\bfrom\b|\bexport\b"),
    ],
    "typescript": [
        ("Arrow functions", r"=>"),
        ("Template literals", r"`"),
        ("Destructuring", r"\b(?:const|let|var)\s*[\[{]"),
        ("Async/Await", r"\b(?:async|await)\b"),
        ("Optional chaining", r"\?\."),
        ("Nullish coalescing", r"\?\?"),
        ("Type annotations", r":\s*(?:string|number|boolean|void|any|unknown)\b"),
        ("Generics", r"<[A-Z]\w*(\s*,\s*[A-Z]\w*)*>"),
        ("Interfaces/Types", r"\b(?:interface|type)\s+[A-Z]\w*"),
        ("ES modules", r"\bimport\b[^\n]*\bfrom\b|\bexport\b"),
    ],
    "python": [
        ("f-strings", r"f['\"]"),
        ("Async/Await", r"\b(?:async|await)\b"),
        ("Type hints", r"->\s*[\w\[\]]+|:\s*(?:int|str|float|bool|list|dict|List|Dict|Optional|Any)\b"),
        ("Walrus operator", r":="),
        ("Dataclasses", r"@dataclass"),
        ("Comprehensions", r"\[[^\]]*\bfor\b[^\]]*\]|\{[^}]*\bfor\b[^}]*\}"),
        ("Decorators", r"(?m)^\s*@\w+"),
        ("Context managers", r"\bwith\b[^\n]*:"),
        ("f-string formatting", r"\{[^}]*:[^}]*\}"),
        ("Unpacking", r"\*\*|\*(?=\w+\s*[,)=])"),
    ],
}

DEFAULT_FEATURES = [
    ("Inline functions", r"=>|\blambda\b"),
    ("String interpolation", r"`|\$\{|f['\"]"),
    ("Imports", r"(?m)^\s*(?:import|from|require|use|include)\b"),
    ("Generics/Templates", r"<[A-Z]\w*>"),
    ("Trailing commas", r",\s*[\]}\)]"),
    ("Unicode symbols", r"[\u2190-\u21FF\u2600-\u27BF]"),
    ("Long descriptive names", r"\b[a-z]+(?:[A-Z][a-z]+){2,}\b"),
    ("Comments with articles", r"(?i)(?://|#|/\*)\s*(the|this|a|an|we|you)\b"),
    ("Annotations", r"@\w+"),
    ("Emoji", r"[\U0001F300-\U0001FAFF]"),
]


def detect_language(filename):
    base = filename.replace("\\", "/").rsplit("/", 1)[-1]
    if "." not in base:
        return "unknown"
    ext = base.rsplit(".", 1)[-1].lower()
    return LANG_BY_EXT.get(ext, "unknown")


def _clamp(v, lo=0.0, hi=100.0):
    return max(lo, min(hi, v))


# --------------------------------------------------------------------------
# Signals
# --------------------------------------------------------------------------

IDENT_RE = re.compile(r"\b[A-Za-z_$][A-Za-z0-9_$]*\b")


def _extract_comments(lines, lang):
    """Return (comment_line_count, comment_texts)."""
    line_pref = LINE_COMMENT.get(lang, [])
    block = BLOCK_COMMENT.get(lang)
    comment_lines = 0
    texts = []
    in_block = False
    for raw in lines:
        s = raw.strip()
        if not s:
            continue
        if in_block:
            comment_lines += 1
            texts.append(s)
            if block and block[1] in s:
                in_block = False
            continue
        if block and s.startswith(block[0]):
            comment_lines += 1
            body = s[len(block[0]):]
            if block[1] in body:
                texts.append(body.split(block[1])[0].strip())
            else:
                in_block = True
                texts.append(body.strip())
            continue
        for pref in line_pref:
            if s.startswith(pref):
                comment_lines += 1
                texts.append(s[len(pref):].strip())
                break
    return comment_lines, texts


def signal_generic_naming(identifiers):
    uniq = set(identifiers)
    total = len(uniq)
    if total == 0:
        return 0.0, ["No identifiers found"]
    generic = sum(1 for i in uniq if i.lower() in GENERIC_NAMES or i in GENERIC_NAMES)
    ratio = generic / total
    score = _clamp(ratio * 250)
    return score, [
        "Total unique identifiers: %d" % total,
        "AI-signature names: %d/%d (%d%%)" % (generic, total, round(ratio * 100)),
    ]


def signal_code_density(lines):
    total = len(lines)
    if total == 0:
        return 0.0, ["No lines found"]
    meaningful = sum(1 for l in lines if l.strip())
    pct = meaningful / total * 100
    score = _clamp((pct - 80) * 3.0)
    return score, [
        "Total lines: %d" % total,
        "Meaningful lines: %d (%d%%)" % (meaningful, round(pct)),
    ]


def signal_comments(lines, lang):
    total = len(lines)
    comment_lines, texts = _extract_comments(lines, lang)
    if comment_lines == 0:
        return 12.0, ["No comments found"]
    trivial = 0
    for t in texts:
        low = t.lower()
        if low in TRIVIAL_COMMENT_WORDS or any(low.startswith(w) for w in TRIVIAL_COMMENT_WORDS):
            trivial += 1
    triv_ratio = trivial / comment_lines
    ratio = comment_lines / total if total else 0
    score = _clamp(triv_ratio * 70 + (0 if ratio >= 0.05 else 15))
    return score, [
        "Comment lines: %d/%d (%d%%)" % (comment_lines, total, round(ratio * 100)),
        "Trivial comments: %d (%d%% of comments)" % (trivial, round(triv_ratio * 100)),
    ]


def signal_formatting(lines):
    indents = [len(l) - len(l.lstrip()) for l in lines if l.strip()]
    if len(indents) < 2:
        std = 0.0
    else:
        std = statistics.pstdev(indents)
    score = _clamp((6.0 - std) * 10, 0, 60)
    return score, [
        "Total lines: %d" % len(lines),
        "Indentation std dev: %.1f" % std,
    ]


def signal_error_handling(code_lines, try_count):
    if code_lines == 0:
        return 0.0, ["No code lines found"]
    ratio = try_count / code_lines
    score = _clamp(ratio * 700)
    return score, [
        "Total code lines: %d" % code_lines,
        "Try/catch blocks: %d" % try_count,
    ]


def signal_structure(lines):
    nonblank = [l for l in lines if l.strip()]
    if not nonblank:
        return 0.0, ["No lines found"]
    lengths = [len(l.rstrip()) for l in nonblank]
    mean = statistics.mean(lengths)
    cvd = (statistics.pstdev(lengths) / mean) if mean else 0.0

    raw = 0.0
    if cvd < 0.35:
        raw += 20
    elif cvd < 0.60:
        raw += 14
    elif cvd < 0.90:
        raw += 8
    else:
        raw += 2

    if 45 <= mean <= 95:
        raw += 15
    elif 30 <= mean <= 110:
        raw += 8
    else:
        raw += 3

    blank_ratio = 1 - len(nonblank) / len(lines) if lines else 0
    if blank_ratio < 0.05:
        raw += 10
    elif blank_ratio < 0.12:
        raw += 5

    max_indent = max((len(l) - len(l.lstrip()) for l in lines), default=0)
    raw += 10 if max_indent <= 16 else 4

    fn_count = sum(1 for l in nonblank if re.search(r"\b(function|def|func|fn)\b|=>\s*\{", l))
    if fn_count:
        avg_fn = len(nonblank) / fn_count
        if avg_fn <= 15:
            raw += 5

    raw = min(raw, 60.0)
    score = _clamp(raw / 60.0 * 70)
    return score, [
        "Score: %d/60" % round(raw),
        "Variable line lengths (CV: %.2f)" % cvd,
    ]


def signal_modern(text, lines, lang):
    feats = MODERN_FEATURES.get(lang, DEFAULT_FEATURES)
    found = []
    total_matches = 0
    for name, pat in feats:
        matches = re.findall(pat, text, re.M)
        if matches:
            found.append(name)
            total_matches += len(matches)
    density = total_matches / len(lines) if lines else 0
    score = _clamp((len(found) / len(feats)) * 45 + density * 100 * 0.5)
    return score, [
        "Features found: %d/%d (%d%%)" % (len(found), len(feats), round(len(found) / len(feats) * 100)),
        "Feature density: %d%% of lines use modern features" % round(density * 100),
    ]


# Aggregation weights (higher = contributes more to the final score).
WEIGHTS = {
    "Generic variable naming": 0.22,
    "Code density": 0.12,
    "Comment ratio & trivial comments": 0.12,
    "Formatting consistency": 0.14,
    "Error handling pattern": 0.10,
    "Structure": 0.14,
    "Modern feature use": 0.16,
}


def get_score_class(score):
    if score >= 80:
        return "red"
    if score >= 30:
        return "amber"
    return "green"


def analyze_file(relname, text):
    lang = detect_language(relname)
    lines = text.splitlines()
    code_lines = [l for l in lines if l.strip() and not l.strip().startswith(tuple(LINE_COMMENT.get(lang, ["\x00"])))]
    identifiers = IDENT_RE.findall(text)
    try_count = len(re.findall(r"\b(?:try|except|catch|rescue)\b", text))

    signals = []
    g, gd = signal_generic_naming(identifiers)
    signals.append(("Generic variable naming", g, gd))
    c, cd = signal_code_density(lines)
    signals.append(("Code density", c, cd))
    m, md = signal_comments(lines, lang)
    signals.append(("Comment ratio & trivial comments", m, md))
    f, fd = signal_formatting(lines)
    signals.append(("Formatting consistency", f, fd))
    e, ed = signal_error_handling(len(code_lines), try_count)
    signals.append(("Error handling pattern", e, ed))
    s, sd = signal_structure(lines)
    signals.append(("Structure", s, sd))
    mo, mod = signal_modern(text, lines, lang)
    signals.append(("Modern feature use", mo, mod))

    score = round(sum(WEIGHTS[name] * val for name, val, _ in signals), 1)

    return {
        "filename": relname,
        "language": lang,
        "tag": LANG_TAG.get(lang, "??"),
        "score": score,
        "score_color": get_score_class(score),
        "signals": [
            {"name": name, "score": round(val, 1), "details": det}
            for name, val, det in signals
        ],
    }


def verdict_for(avg_score):
    if avg_score >= 60:
        return "LIKELY AI-GENERATED", "#ef4444"
    if avg_score >= 25:
        return "MIXED / SUSPICIOUS", "#f59e0b"
    return "LIKELY HUMAN-WRITTEN", "#22c55e"


def analyze_project(files):
    """files: list of (relname, text). Returns the per-file portion of the report."""
    analyzed = [analyze_file(name, text) for name, text in files]
    analyzed.sort(key=lambda f: f["score"], reverse=True)
    if not analyzed:
        return {
            "files": [], "total_files": 0, "files_above_threshold": 0,
            "avg_score": 0.0, "min_score": 0.0, "max_score": 0.0,
            "verdict": "NO SOURCE FILES FOUND", "verdict_color": "#f59e0b",
        }
    scores = [f["score"] for f in analyzed]
    avg = statistics.mean(scores)
    verdict, color = verdict_for(avg)
    return {
        "files": analyzed,
        "total_files": len(analyzed),
        "files_above_threshold": sum(1 for s in scores if s >= 80),
        "avg_score": round(avg, 1),
        "min_score": round(min(scores), 1),
        "max_score": round(max(scores), 1),
        "verdict": verdict,
        "verdict_color": color,
    }
