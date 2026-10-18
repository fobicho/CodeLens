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

import detector

# Canonical category identifiers (also the display text).
CAT_SQLI = "Inyección SQL"
CAT_XSS = "Riesgos XSS"
CAT_N1 = "Cuellos de botella de escalabilidad"
CAT_OBS = "Observabilidad"
CAT_SECRETS = "Secretos embebidos"
CAT_UNSAFE = "Llamadas inseguras"
CAT_CRYPTO = "Criptografía débil"
CAT_TESTS = "Cobertura de pruebas"

SEV_CRIT = "Crítico"
SEV_HIGH = "Alto"
SEV_MED = "Medio"
SEV_LOW = "Bajo"

CONF_HIGH = "Alta"
CONF_MED = "Media"

EFF_LOW = "Baja"
EFF_MED = "Media"

SEVERITY_ORDER = {SEV_CRIT: 0, SEV_HIGH: 1, SEV_MED: 2, SEV_LOW: 3}

# Category -> (severity, remediation effort)
CATEGORY_META = {
    CAT_SQLI: (SEV_CRIT, EFF_LOW),
    CAT_XSS: (SEV_HIGH, EFF_LOW),
    CAT_N1: (SEV_HIGH, EFF_MED),
    CAT_OBS: (SEV_HIGH, EFF_LOW),
    CAT_SECRETS: (SEV_CRIT, EFF_LOW),
    CAT_UNSAFE: (SEV_HIGH, EFF_LOW),
    CAT_CRYPTO: (SEV_MED, EFF_LOW),
    CAT_TESTS: (SEV_MED, EFF_MED),
}

TEST_NAME = re.compile(r"(?:^|[/\\])(?i:tests?|__tests__|spec)(?:[/\\]|$)|"
                       r"(?:\.|_)(?i:test|spec)\.|(?:^|[/\\])(?i:test)_"
                       r"|[a-z0-9](?:Tests|Test|Specs|Spec)\.[a-z0-9]+$|"
                       r"(?:^|[/\\])Test[A-Z]")

_TEST_PREFIX = re.compile(r"^(?:test|Test|TEST)[_-]|^Test(?=[A-Z])")
_TEST_SUFFIX = re.compile(r"[._-](?i:tests?|specs?)$|(?<=[a-z0-9])(?:Tests|Test|Specs|Spec)$")


def _is_test_file(relname):
    return bool(TEST_NAME.search(relname))


def _source_stem(relname):
    stem = os.path.basename(relname).split(".")[0]
    trimmed = _TEST_SUFFIX.sub("", _TEST_PREFIX.sub("", stem))
    return (trimmed or stem).lower()


def _line_of(text, index):
    return text.count("\n", 0, index) + 1


def _clip(s, limit=110):
    """One line, short enough to read inside a card."""
    s = " ".join(s.split())
    return s if len(s) <= limit else s[:limit - 1] + "…"


def _line_text(text, index):
    """The whole source line around a match: a fragment like `eval(` proves
    nothing on its own, the line it sits in is what a reviewer checks."""
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    return text[start:] if end == -1 else text[start:end]


def _lines_label(lines, limit=6):
    shown = ", ".join(str(n) for n in lines[:limit])
    return shown + (", …" if len(lines) > limit else "")


# How "log the error" is actually written in each language, so the fix is in
# the language of the file that has the problem instead of always Python.
LOG_SNIPPET = {
    "python": 'logger.exception("fallo al procesar %s", item_id)',
    "javascript": 'console.error("fallo al procesar", err)',
    "typescript": 'console.error("fallo al procesar", err)',
    "csharp": '_logger.LogError(ex, "Fallo al procesar {ItemId}", itemId);',
    "java": 'log.error("Fallo al procesar {}", itemId, e);',
    "kotlin": 'Log.e(TAG, "Fallo al procesar", e)',
    "php": 'error_log($e->getMessage());',
    "go": 'log.Printf("fallo al procesar: %v", err)',
    "ruby": 'Rails.logger.error("fallo: #{e.message}")',
    "rust": 'log::error!("fallo al procesar: {err:?}");',
    "swift": 'NSLog("fallo al procesar: %@", error.localizedDescription)',
}

# Error handlers and the calls that count as "it was logged".
_HANDLER = re.compile(r"\b(catch|except|rescue)\b[^\n]*")
_TRY_ONLY = re.compile(r"\b(?:try|finally)\b[^\n]*")
_LOGGING = re.compile(
    r"(?i)\b(?:log|logger|logging|log(?:error|exception|warning|info|debug|warn|critical|trace)\w*|"
    r"console\.(?:log|error|warn|debug|info|trace|writeline|writelog)|winston|pino|print|println|"
    r"system\.out|fmt\.print\w*|eprintln|nslog|error_log|trace\.(?:write|writeline)|debug\.log)\b")


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
                "category": CAT_SQLI,
                "severity": SEV_CRIT,
                "confidence": CONF_HIGH,
                "location": "%s:%d" % (relname, line),
                "evidence": _clip(_line_text(text, m.start())),
                "evidence_code": True,
                "explanation": "La consulta se arma concatenando valores: lo que llega del usuario "
                               "acaba formando parte del SQL.",
                "estimated_impact": "La base de datos entera queda al alcance de quien sepa escribir "
                                    "la consulta.",
                "recommendation": "Pasa los valores como parámetros de la consulta en lugar de "
                                  "pegarlos al texto del SQL.",
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
                "category": CAT_XSS,
                "severity": SEV_HIGH,
                "confidence": CONF_MED,
                "location": "%s:%d" % (relname, line),
                "evidence": _clip(_line_text(text, m.start())),
                "evidence_code": True,
                "explanation": "Se escribe entrada del usuario en el DOM sin escaparla.",
                "estimated_impact": "El script se ejecuta en el navegador de la víctima: puede "
                                    "robar la sesión o cambiar lo que ve.",
                "recommendation": "Usa textContent en lugar de innerHTML, o sanitiza el HTML "
                                  "con una librería como DOMPurify.",
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
                "category": CAT_N1,
                "severity": SEV_HIGH,
                "confidence": CONF_MED,
                "location": "%s:%d" % (relname, line),
                "evidence": _clip(_line_text(text, lm.end() + dm.start())),
                "evidence_code": True,
                "explanation": "Consulta a la base de datos dentro de un bucle: patrón N+1.",
                "estimated_impact": "El tiempo de respuesta crece con el número de filas y el "
                                    "pool de conexiones se agota antes de terminar la página.",
                "recommendation": "Agrupa las lecturas: obtén todas las filas necesarias en una "
                                  "sola consulta (WHERE id IN (...)) o usa un join/loader.",
            })
            break
    return findings


def _scan_observability(relname, text):
    handlers = [(m.group(1), _line_of(text, m.start())) for m in _HANDLER.finditer(text)]
    if not handlers:
        m = _TRY_ONLY.search(text)
        if not m:
            return []
        handlers = [("try/finally", _line_of(text, m.start()))]
    if _LOGGING.search(text):
        return []
    lang = detector.detect_language(relname)
    lines = [n for _, n in handlers]
    return [{
        "category": CAT_OBS,
        # One or two swallowed errors is an oversight; a file that swallows
        # every error it meets is a pattern, and patterns are what bite.
        "severity": SEV_HIGH if len(handlers) > 2 else SEV_MED,
        "confidence": CONF_HIGH,
        "location": "%s:%d" % (relname, lines[0]),
        "evidence": "%s %s (%s %s) sin registro" % (
            _n(len(handlers), "bloque", "bloques"), handlers[0][0],
            "líneas" if len(lines) > 1 else "línea", _lines_label(lines)),
        "evidence_code": False,
        "explanation": "La excepción se captura y se descarta: el manejador no deja rastro del fallo.",
        "estimated_impact": "Cuando algo falla en producción no hay traza de qué se rompió ni con "
                            "qué datos, así que el incidente se investiga a ciegas.",
        "recommendation": "Registra el error dentro del manejador, con el contexto que permita "
                          "reproducirlo.",
        "snippet": LOG_SNIPPET.get(lang),
    }]


def _scan_secrets(relname, text):
    findings = []
    pat = (r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|"
           r"private[_-]?key|auth[_-]?token)\b\s*[:=]\s*[\"'][^\"'\n]{6,}[\"']")
    for m in re.finditer(pat, text, re.M):
        line = _line_of(text, m.start())
        findings.append({
            "category": CAT_SECRETS,
            "severity": SEV_CRIT,
            "confidence": CONF_MED,
        "location": "%s:%d" % (relname, line),
        # The report must never echo the secret it found.
        "evidence": _clip(re.sub(r"""(["'])[^"'\n]*\1""", "\\1…\\1", _line_text(text, m.start()))),
        "evidence_code": True,
        "explanation": "Hay un valor con aspecto de credencial escrito en el código.",
        "estimated_impact": "El secreto viaja en el historial de git y en los logs: rotarlo es la "
                            "única salida.",
        "recommendation": "Mueve los secretos a variables de entorno o a un gestor de "
                          "secretos; rota el valor expuesto.",
        })
    return findings


def _scan_unsafe(relname, text):
    findings = []
    pats = [
        (r"\beval\s*\(", "eval() ejecuta código arbitrario y es un sumidero habitual de inyección."),
        (r"\bexec\s*\(", "exec() ejecuta entrada arbitraria y es un sumidero habitual de inyección."),
        (r"os\.system\s*\(", "os.system() ejecuta un comando de shell sin escapar la entrada."),
        (r"subprocess\.\w+\([^)]*shell\s*=\s*True",
         "subprocess con shell=True permite inyección de shell."),
    ]
    for pat, expl in pats:
        for m in re.finditer(pat, text, re.M):
            line = _line_of(text, m.start())
            findings.append({
                "category": CAT_UNSAFE,
                "severity": SEV_HIGH,
                "confidence": CONF_MED,
                "location": "%s:%d" % (relname, line),
                "evidence": _clip(_line_text(text, m.start())),
                "evidence_code": True,
                "explanation": expl,
                "estimated_impact": "Una entrada no confiable acaba ejecutándose como código.",
                "recommendation": "Evita la evaluación dinámica; valida y escapa la entrada, y "
                                  "prefiere APIs parametrizadas antes que cadenas de shell.",
            })
    return findings


def _scan_weak_crypto(relname, text):
    findings = []
    pat = r"(?i)\b(?:md5|sha1)\b|hashlib\.(?:md5|sha1)\s*\(|createHash\(\s*['\"](?:md5|sha1)"
    for m in re.finditer(pat, text, re.M):
        line = _line_of(text, m.start())
        findings.append({
            "category": CAT_CRYPTO,
            "severity": SEV_MED,
            "confidence": CONF_MED,
        "location": "%s:%d" % (relname, line),
        "evidence": _clip(_line_text(text, m.start())),
        "evidence_code": True,
        "explanation": "MD5/SHA-1 están criptográficamente rotos para uso de seguridad.",
        "estimated_impact": "Los hashes se colisionan o se fuerzan por fuerza bruta: no sirven "
                            "ni para integridad ni para guardar contraseñas.",
            "recommendation": "Usa SHA-256+ para integridad y bcrypt/argon2 para contraseñas.",
        })
    return findings


def _scan_test_coverage(relnames):
    """How many source files have no test next to them, by shared name."""
    sources = [r for r in relnames if not _is_test_file(r)]
    if not sources:
        return 0
    covered = {_source_stem(r) for r in relnames if _is_test_file(r)}
    return len([1 for s in sources if _source_stem(s) not in covered])


def collect_findings(files):
    """files: list of (relname, text)."""
    findings = []
    for relname, text in files:
        lang = detector.detect_language(relname)
        batch = (_scan_sql_injection(relname, text)
                 + _scan_xss(relname, text)
                 + _scan_n_plus_one(relname, text)
                 + _scan_observability(relname, text)
                 + _scan_secrets(relname, text)
                 + _scan_unsafe(relname, text)
                 + _scan_weak_crypto(relname, text))
        for f in batch:
            f["language"] = lang
            f["language_tag"] = detector.LANG_TAG.get(lang, "??")
        findings += batch

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


def _n(count, singular, plural):
    return "%d %s" % (count, singular if count == 1 else plural)


def compute_scores(findings, files, untested):
    c = _count_sev(findings, SEV_CRIT)
    h = _count_sev(findings, SEV_HIGH)
    m = _count_sev(findings, SEV_MED)

    security = 100 - (c * 22 + h * 8 + m * 3)
    performance = 100 - (_count_cat(findings, CAT_N1) * 18)
    quality = 100 - (c * 12 + h * 5 + m * 2)
    maintainability = 100 - (m * 6 + h * 4) - min(30, untested)
    total_sources = max(1, len([1 for r, _ in files if not _is_test_file(r)]))
    testability = round(100 * (1 - untested / total_sources))
    scalability = 100 - (_count_cat(findings, CAT_N1) * 20) - min(20, untested)

    def clamp(v):
        return max(0, min(100, round(v)))

    return [
        {"category": "Calidad del código", "score": clamp(quality)},
        {"category": "Mantenibilidad", "score": clamp(maintainability)},
        {"category": "Rendimiento", "score": clamp(performance)},
        {"category": "Seguridad", "score": clamp(security)},
        {"category": "Testabilidad", "score": clamp(testability)},
        {"category": "Escalabilidad", "score": clamp(scalability)},
    ]


def architecture_review(files, findings, untested):
    relnames = [r for r, _ in files]
    low = [r.lower() for r in relnames]
    has = lambda *keys: any(any(k in r for k in keys) for r in low)

    if has("controller") and has("service") and has("repositor"):
        soc = "La separación de capas parece razonable (controladores/servicios/repositorios)."
    elif has("controller", "route", "handler") or has("service"):
        soc = "Se detecta un capado parcial; la separación de responsabilidades puede mejorar."
    else:
        soc = "No se detecta una separación de capas clara; considera introducir capas."

    if has("package.json", "requirements.txt", "pom.xml", "go.mod", "cargo.toml", "composer.json"):
        dep = "La gestión de dependencias parece saludable."
    else:
        dep = "No se detecta un manifiesto de dependencias; la gestión de dependencias no está clara."

    layering = ("Se respetan las capas arquitectónicas." if has("controller", "service", "repositor")
                else "Las capas arquitectónicas solo están definidas parcialmente.")

    if has("model", "entities", "entity", "dto", "domain"):
        domain = "El modelo de dominio parece razonablemente diseñado."
    else:
        domain = "No se detecta un modelo de dominio explícito (modelos/entidades/DTOs)."

    if untested > 0:
        test_strategy = "La estrategia de pruebas parece incompleta: %s sin pruebas" % _n(
            untested, "archivo fuente", "archivos fuente")
    else:
        test_strategy = "La estrategia de pruebas parece adecuada: todos los archivos fuente tienen pruebas."

    data_access = ("Los patrones de acceso a datos parecen optimizados." if has("repositor", "dao", "db", "client")
                   else "No se detecta una capa de acceso a datos clara.")

    sqli = _count_cat(findings, CAT_SQLI)
    xss = _count_cat(findings, CAT_XSS)
    secrets = _count_cat(findings, CAT_SECRETS)
    security_posture = ("Preocupaciones de seguridad: %s de inyección SQL, %s de "
                        "XSS, %s de exposición de datos sensibles." % (
                            _n(sqli, "riesgo", "riesgos"),
                            _n(xss, "riesgo", "riesgos"),
                            _n(secrets, "problema", "problemas")))

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
        tag = f.get("language_tag")
        impact = SEV_CRIT if sev == SEV_CRIT else (SEV_HIGH if sev == SEV_HIGH else SEV_MED)
        plan.append({
            "priority": priority,
            # The language disambiguates two rows of the same category that
            # carry different fixes.
            "issue": "%s%s (severidad %s)" % (cat, " · " + tag if tag and tag != "??" else "", sev),
            "effort": CATEGORY_META.get(cat, (SEV_MED, EFF_MED))[1],
            "impact": impact,
            "recommendation": rec,
        })
        priority += 1
        if priority > 15:
            break
    return plan


def build_audit(files):
    findings = collect_findings(files)
    untested = _scan_test_coverage([r for r, _ in files])
    return {
        "scores": compute_scores(findings, files, untested),
        "architecture_review": architecture_review(files, findings, untested),
        "findings": findings,
        "action_plan": build_action_plan(findings),
    }
