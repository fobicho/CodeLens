# CodeLens 🔍

> Local code analysis tool — detect AI-generated patterns and audit your codebase.

Upload a **`.zip` or `.rar`** archive of any project and instantly get:

- **AI Detection** — seven per-file signals combined into a 0–100 score with a
  verdict per file (*Clean*, *Suspicious*, or *Likely AI*) and an overall verdict.
- **Codebase Audit** — category scores (Quality, Maintainability, Performance,
  Security, Testability, Scalability), architecture review, static security
  findings (SQLi, XSS, N+1 queries, hardcoded secrets, weak crypto), and a
  prioritized action plan.

Everything runs **100% locally** — no code leaves your machine, no API keys needed.

## Requirements

- Python 3.8+ (standard library only)
- For `.rar`: one of
  - WinRAR installed (provides `UnRAR.exe`), or
  - `pip install rarfile` plus `unrar` on `PATH`

`.zip` needs nothing extra.

## Quick Start

```bash
python server.py                # opens in browser at http://127.0.0.1:8000
python server.py --port 9000    # custom port
python server.py --no-browser   # start without auto-opening browser
```

Then **drag & drop** a `.zip` or `.rar` archive onto the page, or click to select.

After analysis completes, click **Download report (.md)** to save the full
analysis as a Markdown file — summary, per-file signals, audit scores, findings,
and the prioritized action plan. The report is generated client-side; nothing
leaves your machine.

## Architecture

```
browser --(raw bytes → POST /analyze?filename=x.zip)--> server.py
                                                         |
                                          extractor.py  → safe extract + collect sources
                                          detector.py → per-file AI signals → scored
                                          audit.py    → findings, scores, arch review
                                                         |
browser <-------------------- JSON report ---------------
```

## AI Detection Signals

Each signal scores 0–100 (higher = more AI-like). Weighted average produces the
final score.

| Signal | What it measures |
|---|---|
| Generic variable naming | Share of AI-typical names (`data`, `result`, `temp`) |
| Code density | Ratio of meaningful vs total lines |
| Comment ratio | Too few or too many trivial comments |
| Formatting consistency | Abnormally low indentation variance |
| Error handling | Density of defensive try/catch blocks |
| Structure | Line-length uniformity, spacing patterns |
| Modern feature use | Breadth and density of language features |

**Thresholds:** `≥80` Likely AI · `30–79` Suspicious · `<30` Clean

Heuristics are calibrated so typical human-written code scores ~15–25. They're a
triage aid, not forensic evidence.

## Audit Categories

| Category | Checks for |
|---|---|
| **Security** | SQL injection, XSS, hardcoded secrets, weak crypto |
| **Scalability** | N+1 queries, bottleneck patterns |
| **Observability** | Error handling without logging |
| **Code Quality** | Unsafe calls (`eval`, `exec`), general issues |
| **Maintainability** | Test coverage, documentation gaps |
| **Testability** | Untested source files ratio |

## Tech Stack

- **Runtime:** Python 3.8+ (stdlib only — no external dependencies)
- **Archive support:** `.zip` (stdlib), `.rar` (WinRAR or `rarfile` package)
- **Server:** `http.server` ThreadingHTTPServer
- **UI:** Single-page vanilla HTML/CSS/JS

## Limitations

- Heuristic-based — not a replacement for real SAST tools or human review.
- Only accepts `.zip` and `.rar` archives.
- No cloud connection; analysis happens entirely in-process.
