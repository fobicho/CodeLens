"""
CodeLens - codebase audit engine.

Produces the "Codebase Audit" tab payload: category scores, an architecture
review, static findings (SQL injection, XSS, N+1 queries, observability gaps,
hardcoded secrets, unsafe calls, weak crypto) and a prioritized action plan.

This is intentionally heuristic/pattern-based - it is a triage aid, not a
replacement for a real SAST tool.
"""

import os
import re

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

# Category -> (severity, remediation effort)
CATEGORY_META = {
    "SQL Injection Risks": ("Critical", "Low"),
    "XSS Risks": ("High", "Low"),
    "Scalability Bottlenecks": ("High", "Medium"),
    "Observability": ("High", "Low"),
    "Hardcoded Secrets": ("Critical", "Low"),
    "Unsafe Calls": ("High", "Low"),
    "Weak Cryptography": ("Medium", "Low"),
    "Test Coverage": ("Medium", "Medium"),
}

TEST_NAME = re.compile(r"(?:^|[/\\])(?:tests?|__tests__|spec)(?:[/\\]|$)|"
                       r"(?:\.|_)(?:test|spec)\.|(?:^|[/\\])test_")


def _is_test_file(relname):
    return bool(TEST_NAME.search(relname))


def _line_of(text, index):
    return text.count("\n", 0, index) + 1


def _find(relname, text, pattern, category, confidence, explanation,
          impact, recommendation, line_scan=False):
    out = []
    for m in re.finditer(pattern, text, re.M):
        if line_scan:
            line = text.count("\n", 0, m.start()) + 1
            loc = "%s:%d" % (relname, line)
        else:
            loc = relname
        out.append({
            "category": category,
            "severity": CATEGORY_META.get(category, ("Medium", "Low"))[0],
            "confidence": confidence,
            "location": loc,
            "explanation": explanation,
            "estimated_impact": impact,
            "recommendation": recommendation,
        })
    return out


def _scan_sql_injection(relname, text):
    findings = []
    sql_kw = r"(?:select\s+.+?\s+from|insert\s+into|update\s+.+?\s+set|delete\s+from)"
    patterns = [
        r"(?i)\b(?:query|execute|exec|raw)\s*\(\s*`[^`]*\$\{[^}]+\}[^`]*`",
        r"(?i)\b(?:query|execute|exec|raw)\s*\(\s*[\"'][^\"'\n]*[\"']\s*(?:\+|%|\.format|\bf\b)",
        r"(?i)(?:" + sql_kw + r")[^\n;\"'`]*\$\{",
        r"(?i)(?:" + sql_kw + r")[^\n;\"'`]*\{[a-zA-Z_][a-zA-Z0-9_]*\}",
    ]
    for pat in patterns:
        for m in re.finditer(pat, text, re.M):
            line = _line_of(text, m.start())
            findings.append({
                "category": "SQL Injection Risks",
                "severity": "Critical",
                "confidence": "High",
                "location": "%s:%d" % (relname, line),
                "explanation": "SQL query uses string interpolation. Variable values are "
                               "directly embedded into the query.",
                "estimated_impact": "Critical security vulnerability. SQL injection can "
                                    "compromise the entire database.",
                "recommendation": "Use parameterized queries, e.g. db.query('SELECT * FROM "
                                  "users WHERE id = $1', [userId]).",
            })
    return findings


def _scan_xss(relname, text):
    findings = []
    patterns = [
        r"\.innerHTML\s*=",
        r"dangerouslySetInnerHTML",
        r"document\.write\s*\(",
        r"(?:res|response)\.send\s*\(\s*`[^`]*\$\{",
    ]
    for pat in patterns:
        for m in re.finditer(pat, text, re.M):
            line = _line_of(text, m.start())
            findings.append({
                "category": "XSS Risks",
                "severity": "High",
                "confidence": "Medium",
                "location": "%s:%d" % (relname, line),
                "explanation": "Value rendered into an HTML context. Rendering "
                               "user-controlled content without sanitization allows XSS.",
                "estimated_impact": "Critical security vulnerability. XSS can steal user "
                                    "sessions, deface pages, or redirect users.",
                "recommendation": "Use textContent instead of innerHTML, or sanitize HTML "
                                  "with a library like DOMPurify. Never render user input "
                                  "directly into the DOM.",
            })
    return findings


def _scan_n_plus_one(relname, text):
    findings = []
    db_call = r"(?:await\s+)?(?:db|pool|conn|connection|client|sequelize|prisma|"
    db_call += r"repository|\w*[Rr]epository|knex)\s*\.\s*\w+\s*\("
    loop_pat = r"for\s*\([^;]*;[^)]*\)|\.forEach\s*\(|\.map\s*\(\s*async|while\s*\("
    for lm in re.finditer(loop_pat, text, re.M):
        block = text[lm.end():lm.end() + 600]
        dm = re.search(db_call, block)
        if dm:
            line = _line_of(text, lm.start())
            findings.append({
                "category": "Scalability Bottlenecks",
                "severity": "High",
                "confidence": "Medium",
                "location": "%s:%d" % (relname, line),
                "explanation": "Database query inside a loop creates an N+1 query pattern. "
                               "Performance degrades linearly with data volume.",
                "estimated_impact": "High risk under load: response time grows with row "
                                    "count and can exhaust the connection pool.",
                "recommendation": "Batch the reads: fetch all needed rows in one query "
                                  "(WHERE id IN (...)) or use a join/loader.",
            })
            break
    return findings


def _scan_observability(relname, text):
    if not re.search(r"\b(try|except|catch|rescue|finally)\b", text):
        return []
    has_logging = re.search(
        r"\b(logger|log|console\.(?:log|error|warn)|logging|winston|pino|print|println|"
        r"System\.out|fmt\.Print|eprintln)\b", text)
    if has_logging:
        return []
    return [{
        "category": "Observability",
        "severity": "High",
        "confidence": "High",
        "location": relname,
        "explanation": "File has error handling (try/catch/except) but no logging. Errors "
                       "are caught but not recorded, making production debugging nearly "
                       "impossible.",
        "estimated_impact": "High operational risk: silent failures are invisible in "
                            "production, slowing incident response.",
        "recommendation": "Log inside every error handler, e.g. "
                          "logger.error('Operation failed', exc_info=True).",
    }]


def _scan_secrets(relname, text):
    findings = []
    pat = (r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|"
           r"private[_-]?key|auth[_-]?token)\b\s*[:=]\s*[\"'][^\"'\n]{6,}[\"']")
    for m in re.finditer(pat, text, re.M):
        line = _line_of(text, m.start())
        findings.append({
            "category": "Hardcoded Secrets",
            "severity": "Critical",
            "confidence": "Medium",
            "location": "%s:%d" % (relname, line),
            "explanation": "A credential-like value is hardcoded in source. Secrets in code "
                           "leak through version control and log files.",
            "estimated_impact": "Critical security vulnerability. Leaked credentials can "
                                "grant unauthorized access to systems and data.",
            "recommendation": "Move secrets to environment variables or a secrets manager; "
                              "rotate the exposed value.",
        })
    return findings


def _scan_unsafe(relname, text):
    findings = []
    pats = [
        (r"\beval\s*\(", "eval() executes arbitrary code and is a common injection sink."),
        (r"\bexec\s*\(", "exec() executes arbitrary input and is a common injection sink."),
        (r"os\.system\s*\(", "os.system() runs a shell command with no input escaping."),
        (r"subprocess\.\w+\([^)]*shell\s*=\s*True",
         "subprocess with shell=True enables shell injection."),
    ]
    for pat, expl in pats:
        for m in re.finditer(pat, text, re.M):
            line = _line_of(text, m.start())
            findings.append({
                "category": "Unsafe Calls",
                "severity": "High",
                "confidence": "Medium",
                "location": "%s:%d" % (relname, line),
                "explanation": expl,
                "estimated_impact": "High security risk: untrusted input can lead to remote "
                                    "code execution.",
                "recommendation": "Avoid dynamic evaluation; validate and escape input, and "
                                  "prefer parameterized APIs over shell strings.",
            })
    return findings


def _scan_weak_crypto(relname, text):
    findings = []
    pat = r"(?i)\b(?:md5|sha1)\b|hashlib\.(?:md5|sha1)\s*\(|createHash\(\s*['\"](?:md5|sha1)"
    for m in re.finditer(pat, text, re.M):
        line = _line_of(text, m.start())
        findings.append({
            "category": "Weak Cryptography",
            "severity": "Medium",
            "confidence": "Medium",
            "location": "%s:%d" % (relname, line),
            "explanation": "MD5/SHA-1 are cryptographically broken for security use.",
            "estimated_impact": "Medium risk: hashes can be collided or brute-forced, "
                                "weakening integrity and password storage.",
            "recommendation": "Use SHA-256+ for integrity and bcrypt/argon2 for passwords.",
        })
    return findings


def _scan_test_coverage(relnames):
    sources = [r for r in relnames if not _is_test_file(r)]
    if not sources:
        return [], 0
    tested = 0
    stems = {}
    for r in relnames:
        if _is_test_file(r):
            stem = os.path.basename(r).split(".")[0]
            stems[stem] = True
    for s in sources:
        stem = os.path.basename(s).split(".")[0]
        if stem in stems:
            tested += 1
    untested = len(sources) - tested
    if untested > 0 and untested > len(sources) * 0.3:
        return [], untested
    return [], untested


def collect_findings(files):
    """files: list of (relname, text)."""
    findings = []
    for relname, text in files:
        findings += _scan_sql_injection(relname, text)
        findings += _scan_xss(relname, text)
        findings += _scan_n_plus_one(relname, text)
        findings += _scan_observability(relname, text)
        findings += _scan_secrets(relname, text)
        findings += _scan_unsafe(relname, text)
        findings += _scan_weak_crypto(relname, text)

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 4))

    deduped = []
    seen = set()
    for f in findings:
        key = (f["category"], f["location"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    return deduped


def _count_sev(findings, sev):
    return sum(1 for f in findings if f["severity"] == sev)


def _count_cat(findings, cat):
    return sum(1 for f in findings if f["category"] == cat)


def compute_scores(findings, files, untested):
    c = _count_sev(findings, "Critical")
    h = _count_sev(findings, "High")
    m = _count_sev(findings, "Medium")

    security = 100 - (c * 22 + h * 8 + m * 3)
    performance = 100 - (_count_cat(findings, "Scalability Bottlenecks") * 18)
    quality = 100 - (c * 12 + h * 5 + m * 2)
    maintainability = 100 - (m * 6 + h * 4) - min(30, untested)
    total_sources = max(1, len([1 for r, _ in files if not _is_test_file(r)]))
    testability = round(100 * (1 - untested / total_sources))
    scalability = 100 - (_count_cat(findings, "Scalability Bottlenecks") * 20) - min(20, untested)
    observability = _count_cat(findings, "Observability") * 10

    def clamp(v):
        return max(0, min(100, round(v)))

    return [
        {"category": "Code Quality", "score": clamp(quality)},
        {"category": "Maintainability", "score": clamp(maintainability)},
        {"category": "Performance", "score": clamp(performance)},
        {"category": "Security", "score": clamp(security)},
        {"category": "Testability", "score": clamp(testability)},
        {"category": "Scalability", "score": clamp(scalability)},
    ]


def architecture_review(files, findings, untested):
    relnames = [r for r, _ in files]
    low = [r.lower() for r in relnames]
    has = lambda *keys: any(any(k in r for k in keys) for r in low)

    if has("controller") and has("service") and has("repositor"):
        soc = "Layer separation appears reasonable (controllers/services/repositories)."
    elif has("controller", "route", "handler") or has("service"):
        soc = "Partial layering detected; separation of concerns can be improved."
    else:
        soc = "No clear layer separation detected; consider introducing layers."

    if has("package.json", "requirements.txt", "pom.xml", "go.mod", "cargo.toml", "composer.json"):
        dep = "Dependency management appears healthy."
    else:
        dep = "No dependency manifest detected; dependency management is unclear."

    layering = ("Architectural layers are respected." if has("controller", "service", "repositor")
                else "Architectural layers are only partially defined.")

    if has("model", "entities", "entity", "dto", "domain"):
        domain = "Domain model appears reasonably designed."
    else:
        domain = "No explicit domain model detected (models/entities/DTOs)."

    if untested > 0:
        test_strategy = "Test strategy appears incomplete: %d untested source files" % untested
    else:
        test_strategy = "Test strategy appears adequate: all source files have tests."

    data_access = ("Data access patterns appear optimized." if has("repositor", "dao", "db", "client")
                   else "No clear data-access layer detected.")

    sqli = _count_cat(findings, "SQL Injection Risks")
    xss = _count_cat(findings, "XSS Risks")
    secrets = _count_cat(findings, "Hardcoded Secrets")
    security_posture = ("Security concerns: %d SQL injection risks, %d XSS risks, "
                        "%d sensitive data exposure issues." % (sqli, xss, secrets))

    return {
        "separation_of_concerns": soc,
        "dependency_management": dep,
        "layering": layering,
        "domain_modeling": domain,
        "test_strategy": test_strategy,
        "data_access_strategy": data_access,
        "security_posture": security_posture,
    }


def build_action_plan(findings):
    seen = {}
    for f in findings:
        key = (f["category"], f["recommendation"])
        if key in seen:
            continue
        seen[key] = f
    plan = []
    priority = 1
    for (cat, rec), f in sorted(seen.items(), key=lambda kv: SEVERITY_ORDER.get(kv[1]["severity"], 4)):
        sev = f["severity"]
        impact = "Critical" if sev == "Critical" else ("High" if sev == "High" else "Medium")
        plan.append({
            "priority": priority,
            "issue": "%s (%s severity)" % (cat, sev),
            "effort": CATEGORY_META.get(cat, ("Medium", "Medium"))[1],
            "impact": impact,
            "recommendation": rec,
        })
        priority += 1
        if priority > 15:
            break
    return plan


def build_audit(files):
    findings = collect_findings(files)
    _, untested = _scan_test_coverage([r for r, _ in files])
    return {
        "scores": compute_scores(findings, files, untested),
        "architecture_review": architecture_review(files, findings, untested),
        "findings": findings,
        "action_plan": build_action_plan(findings),
    }
