"""
CWE-NNN — [Title: short description of the weakness]

[One paragraph: what the weakness is, what the demo shows, and what the
vulnerable vs safe endpoints demonstrate. Keep it to 3–5 sentences.]
"""

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI()

# ── Style ─────────────────────────────────────────────────────────────────────

CSS = """
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
"""

# ── Navigation ────────────────────────────────────────────────────────────────

NAV = """
<div class="nav">
    <a href="/">Home</a> |
    <a href="/demo/vulnerable">/demo/vulnerable</a> |
    <a href="/demo/safe">/demo/safe</a>
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


@app.get("/demo/vulnerable", response_class=HTMLResponse)
async def vulnerable():
    # [Implement the vulnerable path. Rename route to match demo context.]
    return f"""
    <html>
    <head><title>CWE-NNN — Vulnerable</title><style>{CSS}</style></head>
    <body>
    {NAV}
    <h1>CWE-NNN — Vulnerable</h1>
    <div class="box bad">
        <p class="tag-vuln">&#9888; VULNERABLE</p>
        <p>[What the vulnerable path does and why it is unsafe.]</p>
    </div>
    </body>
    </html>
    """


@app.get("/demo/safe", response_class=HTMLResponse)
async def safe():
    # [Implement the safe path. Rename route to match demo context.]
    return f"""
    <html>
    <head><title>CWE-NNN — Safe</title><style>{CSS}</style></head>
    <body>
    {NAV}
    <h1>CWE-NNN — Safe</h1>
    <div class="box good">
        <p class="tag-safe">&#10003; SAFE</p>
        <p>[What the safe path does differently and why it is secure.]</p>
    </div>
    </body>
    </html>
    """
