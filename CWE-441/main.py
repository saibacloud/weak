from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
import os

app = FastAPI()

# The directory the server is supposed to serve files from.
# In a real app this might be a shared drive, an S3 prefix, a report folder, etc.
DOCS_DIR = os.path.join(os.path.dirname(__file__), "docs")

CSS = """
body { font-family: sans-serif; padding: 20px; }
.box { border: 1px solid #ddd; padding: 12px; margin: 10px 0; background: #eee; white-space: pre-wrap; font-family: monospace; }
.warn { background: #fff3cd; border-color: #ffc107; padding: 10px; margin: 10px 0; }
.safe-badge { background: #d4edda; border: 1px solid #28a745; padding: 8px 14px; display: inline-block; margin-bottom: 12px; }
input[type=text] { width: 360px; padding: 5px; }
nav { margin-bottom: 20px; }
"""

NAV_VULN = """
<nav>
    <a href="/">Vulnerable Document Portal</a> |
    <a href="/safe">Safe Document Portal</a>
</nav>
"""

NAV_SAFE = """
<nav>
    <a href="/">Vulnerable Document Portal</a> |
    <a href="/safe">Safe Document Portal</a>
</nav>
"""


# --- Vulnerable version ---

@app.get("/", response_class=HTMLResponse)
async def index():
    # List the docs directory so the user knows what's available
    try:
        files = os.listdir(DOCS_DIR)
        file_list = "".join(f"<li><code>{f}</code></li>" for f in files)
    except Exception:
        file_list = "<li>(could not list directory)</li>"

    return f"""
    <html>
    <head><title>Document Portal (Vulnerable)</title><style>{CSS}</style></head>
    <body>
        {NAV_VULN}
        <h1>Document Portal</h1>
        <div class="warn">
            <strong>Demo note:</strong> This is the <strong>vulnerable</strong> version.
            The server (the deputy) reads whatever filename you supply, using its own
            filesystem access. You are not privileged — but the deputy is.
        </div>

        <h3>Available files in <code>docs/</code>:</h3>
        <ul>{file_list}</ul>

        <h3>Read a file:</h3>
        <form method="POST" action="/read">
            <input type="text" name="filename" placeholder="readme.txt" required>
            <button type="submit">Read File</button>
        </form>

        <p>
            <strong>Try:</strong> type <code>readme.txt</code> for a normal file,
            then try <code>../secrets/config.env</code> — the server will happily
            read it on your behalf because you're telling the deputy what to fetch.
        </p>
    </body>
    </html>
    """


@app.post("/read", response_class=HTMLResponse)
async def read_file_vuln(request: Request, filename: str = Form(...)):
    # THE VULNERABILITY:
    # The server (the deputy) has read access to the whole filesystem.
    # The user has no such access — they're just a browser client.
    # But we blindly join whatever the user gives us onto DOCS_DIR and open it.
    # The deputy acts on behalf of the user using ITS OWN authority,
    # without checking whether the resulting path is actually inside docs/.
    # The user is not privileged. The server is. We just lent that privilege out.
    path = os.path.join(DOCS_DIR, filename)

    try:
        with open(path, "r") as f:
            content = f.read()
        result_html = f"""
        <div class="box">
            <strong>File: {filename}</strong>
            <hr>
{content}
        </div>
        """
    except FileNotFoundError:
        result_html = f"<div class='box'>File not found: <code>{filename}</code></div>"
    except Exception as e:
        result_html = f"<div class='box'>Error reading file: {e}</div>"

    return f"""
    <html>
    <head><title>Document Portal (Vulnerable)</title><style>{CSS}</style></head>
    <body>
        {NAV_VULN}
        <h1>Document Portal</h1>
        <div class="warn">
            <strong>Demo note:</strong> Vulnerable version — no path validation.
        </div>
        <h3>Result:</h3>
        {result_html}
        <a href="/">← Back</a>
    </body>
    </html>
    """


# --- Safe version ---

@app.get("/safe", response_class=HTMLResponse)
async def safe_index():
    try:
        files = os.listdir(DOCS_DIR)
        file_list = "".join(f"<li><code>{f}</code></li>" for f in files)
    except Exception:
        file_list = "<li>(could not list directory)</li>"

    return f"""
    <html>
    <head><title>Document Portal (Safe)</title><style>{CSS}</style></head>
    <body>
        {NAV_SAFE}
        <h1>Document Portal (Safe)</h1>
        <div class="safe-badge">✓ Path validation enforced — traversal blocked</div>

        <h3>Available files in <code>docs/</code>:</h3>
        <ul>{file_list}</ul>

        <h3>Read a file:</h3>
        <form method="POST" action="/safe/read">
            <input type="text" name="filename" placeholder="readme.txt" required>
            <button type="submit">Read File</button>
        </form>

        <p>
            Try <code>../secrets/config.env</code> here — the server will reject it
            before the deputy's authority is ever exercised outside the allowed directory.
        </p>
    </body>
    </html>
    """


@app.post("/safe/read", response_class=HTMLResponse)
async def read_file_safe(request: Request, filename: str = Form(...)):
    # THE FIX:
    # Before the deputy reads anything, resolve the real absolute path
    # and confirm it sits inside DOCS_DIR.
    # The deputy only acts if the request is within its sanctioned scope.
    # os.path.realpath resolves symlinks and .. components, then we check
    # the resolved path actually starts with the allowed directory.
    resolved = os.path.realpath(os.path.join(DOCS_DIR, filename))
    allowed_base = os.path.realpath(DOCS_DIR)

    if not resolved.startswith(allowed_base + os.sep) and resolved != allowed_base:
        return f"""
        <html>
        <head><title>Document Portal (Safe)</title><style>{CSS}</style></head>
        <body>
            {NAV_SAFE}
            <h1>Document Portal (Safe)</h1>
            <div class="safe-badge">✓ Path validation enforced — traversal blocked</div>
            <div class="box">
                <strong>Access denied.</strong><br>
                Resolved path is outside the allowed directory.<br>
                <code>{resolved}</code> is not inside <code>{allowed_base}</code>
            </div>
            <a href="/safe">← Back</a>
        </body>
        </html>
        """

    try:
        with open(resolved, "r") as f:
            content = f.read()
        result_html = f"""
        <div class="box">
            <strong>File: {filename}</strong>
            <hr>
{content}
        </div>
        """
    except FileNotFoundError:
        result_html = f"<div class='box'>File not found: <code>{filename}</code></div>"
    except Exception as e:
        result_html = f"<div class='box'>Error reading file: {e}</div>"

    return f"""
    <html>
    <head><title>Document Portal (Safe)</title><style>{CSS}</style></head>
    <body>
        {NAV_SAFE}
        <h1>Document Portal (Safe)</h1>
        <div class="safe-badge">✓ Path validation enforced — traversal blocked</div>
        <h3>Result:</h3>
        {result_html}
        <a href="/safe">← Back</a>
    </body>
    </html>
    """
