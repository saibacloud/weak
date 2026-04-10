"""
CWE-403 - Exposure of File Descriptor to Unintended Control Sphere

The server opens secrets.txt at startup and holds the fd open for the
lifetime of the process (simulating a persistent privileged resource:
a config file, credential store, admin socket, etc.).

When a request comes in and the server spawns a subprocess:

  VULNERABLE  /process/vulnerable  →  close_fds=False (or omitted pre-Py3.2)
              The child inherits every open fd. It can enumerate
              /proc/self/fd/, find secrets.txt, and read it in full -
              without ever knowing the file's path.

  SAFE        /process/safe        →  close_fds=True
              All fds above stderr are closed before exec.
              The child finds nothing beyond 0 / 1 / 2.

Watch the Network tab: both endpoints return JSON so you can see
exactly what the subprocess discovered in each case.
"""

import json
import os
import subprocess
import sys
import datetime

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

# ── Open the secret file at startup; keep the fd alive ───────────────────────
_SECRET_PATH = os.path.join(os.path.dirname(__file__), "secrets.txt")
_secret_fh   = open(_SECRET_PATH, "r")          # fd stays open forever
SECRET_FD    = _secret_fh.fileno()
os.set_inheritable(SECRET_FD, True)              # ← override O_CLOEXEC so child can inherit

app = FastAPI()

# ── Shared log (last N subprocess runs, shown on home page) ──────────────────
run_log: list[dict] = []
MAX_LOG = 20


# ── Helper ────────────────────────────────────────────────────────────────────

def spawn_worker(close_fds: bool) -> tuple[list, str]:
    """
    Spawn worker.py as a subprocess.
    Returns (findings_list, raw_stdout).
    """
    worker = os.path.join(os.path.dirname(__file__), "worker.py")
    result = subprocess.run(
        [sys.executable, worker],
        capture_output=True,
        text=True,
        close_fds=close_fds,   # ← the single flag that decides everything
        timeout=5,
    )
    try:
        findings = json.loads(result.stdout)
    except json.JSONDecodeError:
        findings = []
    return findings, result.stdout.strip()


# ── CSS (identical style to CWE-370 reference) ────────────────────────────────

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
#result-panel { display: none; }
#result-json { max-height: 400px; overflow: auto; background: #f5f5f5; padding: 10px;
               border: 1px solid #bbb; }
"""

NAV = """
<div class="nav">
    <a href="/">Home</a> |
    <button onclick="runEndpoint('vulnerable')">▶ /process/vulnerable</button> |
    <button onclick="runEndpoint('safe')">▶ /process/safe</button>
</div>
"""

SCRIPT = """
async function runEndpoint(mode) {
    const panel = document.getElementById('result-panel');
    const pre   = document.getElementById('result-json');
    panel.style.display = 'block';
    pre.textContent = 'Loading...';
    try {
        const resp = await fetch('/process/' + mode);
        const data = await resp.json();
        pre.textContent = JSON.stringify(data, null, 2);
        // update the log table client-side
        const table = document.getElementById('log-table');
        const leaked = (data.inherited_fds || []).filter(f => f.readable).length;
        const badge = leaked
            ? '<span class="tag-vuln">\\u26a0 ' + leaked + ' fd(s) leaked</span>'
            : '<span class="tag-safe">\\u2713 clean</span>';
        const now = new Date().toLocaleTimeString('en-GB', {hour:'2-digit',minute:'2-digit',second:'2-digit'});
        const row = '<tr><td>' + now + '</td><td>' + data.mode
            + '</td><td>' + data.close_fds + '</td><td>' + badge + '</td></tr>';
        // remove the "no runs yet" placeholder if present
        const placeholder = table.querySelector('td[colspan]');
        if (placeholder) placeholder.parentElement.remove();
        // insert after the header row
        table.querySelector('tr').insertAdjacentHTML('afterend', row);
    } catch (e) {
        pre.textContent = 'Error: ' + e.message;
    }
}
"""


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    # Build run log rows
    log_rows = ""
    if run_log:
        for entry in reversed(run_log[-MAX_LOG:]):
            leaked = entry["leaked_count"]
            badge  = (
                f'<span class="tag-vuln">⚠ {leaked} fd(s) leaked</span>'
                if leaked else
                '<span class="tag-safe">✓ clean</span>'
            )
            log_rows += f"""
            <tr>
                <td>{entry['time']}</td>
                <td>{entry['mode']}</td>
                <td>{entry['close_fds']}</td>
                <td>{badge}</td>
            </tr>"""
    else:
        log_rows = "<tr><td colspan='4'>No runs yet - hit an endpoint below.</td></tr>"

    html = f"""
    <html>
    <head><title>CWE-403</title><style>{CSS}</style></head>
    <body>
    {NAV}

    <h1>CWE-403 - File Descriptor Leak</h1>
    <p>
        The server opened <code>secrets.txt</code> at startup (fd&nbsp;<strong>{SECRET_FD}</strong>)
        and keeps it open. When a user request triggers a subprocess, that fd is either
        inherited or closed depending on <code>close_fds</code>.
    </p>

    <div class="box good">
        <p class="tag-safe">✓ SAFE - GET /process/safe</p>
        <p>Spawns <code>worker.py</code> with <code>close_fds=True</code>.</p>
        <p>All fds above stderr are closed before <code>exec()</code>. The worker finds nothing.</p>
    </div>

    <h2>How to Demo</h2>
    <div class="box">
        <ol style="margin:0; padding-left:18px; line-height:1.9;">
            <li>Open DevTools → <strong>Network tab</strong></li>
            <li>Click the <strong>▶ /process/vulnerable</strong> button above -
                inspect the fetch request's Response tab. You will see fd&nbsp;{SECRET_FD} listed with full content.</li>
            <li>Click the <strong>▶ /process/safe</strong> button -
                the <code>inherited_fds</code> array will be empty.</li>
            <li>Compare the two response payloads in the Network tab side by side.</li>
        </ol>
    </div>

    <h2>Response</h2>
    <div class="box" id="result-panel">
        <pre id="result-json"></pre>
    </div>

    <h2>Run Log</h2>
    <div class="box">
        <table id="log-table">
            <tr><th>Time</th><th>Mode</th><th>close_fds</th><th>Result</th></tr>
            {log_rows}
        </table>
    </div>

    <script>{SCRIPT}</script>
    </body>
    </html>
    """
    return html


@app.get("/process/vulnerable", response_class=JSONResponse)
def process_vulnerable():
    """
    VULNERABLE: close_fds=False
    The subprocess inherits all open file descriptors from the server process.
    """
    findings, raw = spawn_worker(close_fds=False)

    run_log.append({
        "time":        datetime.datetime.now().strftime("%H:%M:%S"),
        "mode":        "VULNERABLE",
        "close_fds":   "False",
        "leaked_count": sum(1 for f in findings if f.get("readable")),
    })

    # Annotate any fd that matches our known secret fd
    for f in findings:
        f["is_secret_fd"] = (f["fd"] == SECRET_FD)

    return JSONResponse({
        "mode":          "VULNERABLE",
        "close_fds":     False,
        "server_secret_fd": SECRET_FD,
        "explanation":   (
            "close_fds=False - the subprocess inherited every open fd. "
            "It enumerated /proc/self/fd/ and read whatever it could reach. "
            "Look for is_secret_fd=true in inherited_fds."
        ),
        "inherited_fds": findings,
        "cwe":           "CWE-403",
    })


@app.get("/process/safe", response_class=JSONResponse)
def process_safe():
    """
    SAFE: close_fds=True
    All fds above stderr are closed before exec. The subprocess is blind.
    """
    findings, raw = spawn_worker(close_fds=True)

    run_log.append({
        "time":        datetime.datetime.now().strftime("%H:%M:%S"),
        "mode":        "SAFE",
        "close_fds":   "True",
        "leaked_count": sum(1 for f in findings if f.get("readable")),
    })

    return JSONResponse({
        "mode":          "SAFE",
        "close_fds":     True,
        "server_secret_fd": SECRET_FD,
        "explanation":   (
            "close_fds=True - all fds above stderr were closed before exec. "
            "The subprocess found nothing beyond stdin/stdout/stderr. "
            "inherited_fds should be empty."
        ),
        "inherited_fds": findings,
        "cwe":           "CWE-403",
    })
