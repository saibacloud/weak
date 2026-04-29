# CWE Portfolio Framework Design

> **Scope:** Reference spec for the `weak` repository — a self-contained collection of security weakness demonstrations. Defines the canonical structure, visual standard, README template, and FastAPI code patterns that every demo must follow. Also covers the static portfolio landing page.

**Goal:** Make every CWE demo consistent enough that a new one can be built by copying `_template/`, filling in the blanks, and following the README template — with zero decisions to make about layout, style, or structure.

**Architecture:** Static `index.html` at the repo root acts as the portfolio entry point. Each demo lives in its own `CWE-NNN/` directory and runs independently as a `uvicorn` process. A `_template/` directory provides the canonical skeleton. A spec doc (this file) and the template together are the reference.

**Tech stack:** Python 3, FastAPI, uvicorn, plain HTML/CSS/JS (no external frameworks). CSS is embedded as a module-level string constant in each `main.py`.

---

## 1. Repository Structure

```
weak/
├── index.html                  # Static landing page — open directly in browser
├── README.md                   # Root readme — lists all demos, add index.html to usage
├── docs/
│   └── superpowers/
│       └── specs/
│           └── 2026-04-29-cwe-portfolio-framework-design.md
├── _template/
│   ├── main.py                 # Skeleton FastAPI app — copy and fill in blanks
│   ├── README.md               # Fill-in-the-blank README template
│   └── requirements.txt        # Baseline deps
├── CWE-79/
├── CWE-370/
├── CWE-403/
├── CWE-441/
├── CWE-444/
└── CWE-NNN/                    # Future demos follow the same layout
```

**Rules:**
- Every demo directory is named exactly `CWE-NNN` (zero-padded as needed to match the official CWE ID).
- Every demo contains at minimum: `main.py`, `README.md`, `requirements.txt`.
- Supporting files (e.g. `worker.py`, `secrets.txt`, `internal.py`) are allowed and listed in the README's Files table.
- Virtual environments are named `.venv` and are `.gitignore`d.
- Every demo runs on port **5000** via `uvicorn main:app --reload --port 5000`.

---

## 2. Visual Standard (CSS)

The following CSS block is the canonical style for every demo. It is copied verbatim into the `CSS` module-level constant in `main.py`. Do not modify it; do not add colors.

```css
* { box-sizing: border-box; }
body { font-family: sans-serif; padding: 20px; background: #fff; color: #111; }
h1, h2 { margin-bottom: 6px; }
p  { margin: 4px 0; }
a  { color: #111; }
.nav { margin-bottom: 20px; }
.box { border: 1px solid #bbb; padding: 12px; margin: 10px 0; background: #eee; }
.warn  { border-color: #999; background: #ddd; }
.bad   { border-left: 4px solid #111; }
.good  { border-left: 4px solid #888; }
table  { border-collapse: collapse; width: 100%; margin-top: 8px; }
td, th { padding: 4px 10px; text-align: left; border-bottom: 1px solid #ccc; font-size: 0.9em; }
th     { background: #ddd; }
pre    { margin: 0; white-space: pre-wrap; word-break: break-all; font-size: 0.85em; }
code   { background: #ddd; padding: 1px 4px; border-radius: 2px; font-size: 0.85em; }
.tag-vuln { font-weight: bold; }
.tag-safe { color: #444; font-weight: bold; }
.dim  { color: #666; font-size: 0.85em; }
button { font-family: sans-serif; font-size: 0.9em; padding: 4px 10px; cursor: pointer;
         border: 1px solid #999; background: #ddd; border-radius: 2px; }
button:hover { background: #ccc; }
```

Additional utility classes may be added per-demo below this block if the demo requires them (e.g. a result panel for async fetch demos). The base block above must not be changed.

---

## 3. `_template/main.py` Skeleton

```python
"""
CWE-NNN — [Title: short description of the weakness]

[One paragraph: what the weakness is, what the demo shows, and what the
 vulnerable vs safe endpoints demonstrate. Keep it to 3-5 sentences.]
"""

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI()

# ── Style ─────────────────────────────────────────────────────────────────────

CSS = """
[paste canonical CSS block from spec — do not modify]
"""

# ── Navigation ────────────────────────────────────────────────────────────────

NAV = """
<div class="nav">
    <a href="/">Home</a> |
    <a href="/vulnerable">/vulnerable</a> |
    <a href="/safe">/safe</a>
</div>
"""

# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index():
    return f"""
    <html>
    <head><title>CWE-NNN</title><style>{CSS}</style></head>
    <body>
    {NAV}
    <h1>CWE-NNN — [Title]</h1>
    <p>[Brief description of the weakness and what this demo shows.]</p>

    <h2>How to Demo</h2>
    <div class="box">
        [Step-by-step instructions for the visitor.]
    </div>
    </body>
    </html>
    """


@app.get("/vulnerable", response_class=HTMLResponse)
async def vulnerable():
    # [Implement the vulnerable path here.]
    # Route name and path will differ per demo — rename as needed.
    return f"""
    <html>
    <head><title>CWE-NNN — Vulnerable</title><style>{CSS}</style></head>
    <body>
    {NAV}
    <h1>CWE-NNN — Vulnerable</h1>
    <div class="box bad">
        <p class="tag-vuln">⚠ VULNERABLE</p>
        <p>[What the vulnerable path does and why it is unsafe.]</p>
    </div>
    </body>
    </html>
    """


@app.get("/safe", response_class=HTMLResponse)
async def safe():
    # [Implement the safe path here.]
    # Route name and path will differ per demo — rename as needed.
    return f"""
    <html>
    <head><title>CWE-NNN — Safe</title><style>{CSS}</style></head>
    <body>
    {NAV}
    <h1>CWE-NNN — Safe</h1>
    <div class="box good">
        <p class="tag-safe">✓ SAFE</p>
        <p>[What the safe path does differently and why it is secure.]</p>
    </div>
    </body>
    </html>
    """
```

**Rules:**
- `CSS` and `NAV` are always module-level string constants, defined before routes.
- The module docstring is always present and describes the weakness and demo.
- Every demo has at least one vulnerable route and one safe route. Route names and paths will vary per CWE — rename `/vulnerable` and `/safe` to match the demo's context.
- Inline CSS f-strings only — no separate `.css` files (each demo is self-contained).
- JavaScript, if needed, is a module-level `SCRIPT` constant, same pattern as CSS.

---

## 4. `_template/README.md` Template

Every README follows this exact section order. Section headings are fixed; content is filled in per demo.

```markdown
## CWE-NNN: [Full Title from MITRE]

[One paragraph: what the weakness is and what this demo shows. Match the module docstring.]

---

## 1. Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 2. Start

```bash
uvicorn main:app --reload --port 5000
```

Open: `http://127.0.0.1:5000`

---

## 3. Config

### Files
| File | Purpose |
|------|---------|
| `main.py` | FastAPI app |
| [additional files] | [purpose] |

### Routes
| Route | Method | Purpose |
|-------|--------|---------|
| `/` | GET | Home — overview and demo instructions |
| `/vulnerable[/path]` | [METHOD] | [What it does — why it is vulnerable] |
| `/safe[/path]` | [METHOD] | [What it does — why it is safe] |

---

## 4. Demonstration

### A. Vulnerable — [route or action name]

[Numbered steps. Be explicit: what to open, what to type, what to observe.]

### B. Safe — [route or action name]

[Numbered steps. Show the same actions against the safe endpoint and what changes.]

---

## 5. The Vulnerability in Code

**Vulnerable:**
```[language]
[minimal code snippet showing the unsafe pattern]
```

**Safe:**
```[language]
[minimal code snippet showing the fix]
```

---

## 6. Why It Matters

[3-5 bullet points or short paragraphs. Real-world scenarios where this weakness causes harm. Real-world mitigations beyond the demo fix.]
```

---

## 5. `_template/requirements.txt`

```
fastapi
uvicorn[standard]
```

Add additional dependencies below these two lines as needed for the specific demo.

---

## 6. `index.html` (Portfolio Landing Page)

A static HTML file at the repo root. No server required — open directly in a browser.

**Structure:**
- Page title: "A Weak Repo"
- One-sentence intro: "A collection of self-contained security weakness demonstrations."
- A table listing every demo: CWE number (linked to its directory README), title, one-line description, status (built / stub)
- Usage note: each demo runs independently — `cd CWE-NNN && uvicorn main:app --port 5000`
- Same monochrome aesthetic as the demos (inline `<style>` block using the same CSS palette — `#fff` background, `#111` text, `#bbb` borders, `#eee` boxes, `sans-serif`)

**The table:**

| CWE | Title | Description | Status |
|-----|-------|-------------|--------|
| CWE-79 | Cross-Site Scripting | Reflected and stored XSS via unsanitised output | Built |
| CWE-89 | SQL Injection | Unsanitised query parameter passed to raw SQL | Stub |
| CWE-22 | Path Traversal | User-controlled path escapes the intended directory | Stub |
| CWE-352 | Cross-Site Request Forgery | State-changing request accepted without a CSRF token | Stub |
| CWE-370 | Missing Revocation Re-check | Certificate revocation only checked at login | Built |
| CWE-403 | File Descriptor Leak | Subprocess inherits privileged fd via fork | Built |
| CWE-434 | Unrestricted File Upload | Uploaded file type not validated before saving | Stub |
| CWE-441 | Confused Deputy / SSRF | Server fetches arbitrary URLs using its own network position | Built |
| CWE-444 | HTTP Request Smuggling | Ambiguous Content-Length vs Transfer-Encoding headers exploited | Built |

---

## 7. Rules Summary (Quick Reference)

| Concern | Decision |
|---------|----------|
| Port | Always 5000 |
| Venv name | `.venv` |
| CSS location | Module-level `CSS` constant in `main.py` |
| CSS palette | Monochrome — `#fff`, `#111`, `#bbb`, `#eee`, `#ddd`. No added colors. |
| JS location | Module-level `SCRIPT` constant, injected via f-string |
| NAV location | Module-level `NAV` constant |
| Route pattern | At minimum: one vulnerable route, one safe route |
| README sections | Fixed order: Install → Start → Config → Demonstration → Code → Why It Matters |
| New demo workflow | Copy `_template/`, rename `NNN`, fill blanks, follow README template |
