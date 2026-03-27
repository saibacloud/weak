from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
import secrets
import datetime

app = FastAPI()

# Certificate store: cert_id -> { owner }
certificates = {
    "CERT-ALICE-001": {"owner": "Alice"},
    "CERT-BOB-002":   {"owner": "Bob"},
    "CERT-CAROL-003": {"owner": "Carol"},
}

# Certificate Revocation List (CRL): cert_id -> revoked_at (timestamp string)
# In a real PKI, this list is distributed by the CA and must be re-fetched/re-checked.
revocation_list: dict = {}

# Active sessions: token -> { cert_id, owner, login_at }
# CWE-370: revocation is only checked when the session is CREATED.
# After that, sessions are trusted blindly.
sessions: dict = {}


def is_revoked(cert_id: str) -> bool:
    return cert_id in revocation_list


def cert_status(cert_id: str) -> str:
    if cert_id in revocation_list:
        return f"REVOKED ({revocation_list[cert_id]})"
    return "valid"


CSS = """
body { font-family: sans-serif; padding: 20px; }
.box { border: 1px solid #ddd; padding: 10px; margin: 10px 0; background: #eee; }
table { border-collapse: collapse; }
td, th { padding: 4px 10px; text-align: left; border-bottom: 1px solid #ccc; }
input { width: 220px; padding: 5px; }
"""

# --- Landing page ---


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    # Build certificate table rows
    cert_rows = ""
    for cid, info in certificates.items():
        cert_rows += f"""
        <tr>
            <td>{cid}</td>
            <td>{info['owner']}</td>
            <td>{cert_status(cid)}</td>
        </tr>"""

    # Build active sessions table rows
    session_rows = ""
    if sessions:
        for token, s in sessions.items():
            warn = " [cert revoked]" if is_revoked(
                s['cert_id']) else ""
            session_rows += f"""
            <tr>
                <td>{token[:20]}…</td>
                <td>{s['owner']}</td>
                <td>{s['cert_id']}{warn}</td>
                <td>{s['login_at']}</td>
            </tr>"""
    else:
        session_rows = "<tr><td colspan='4'>No active sessions</td></tr>"

    # Build CRL table rows
    crl_rows = ""
    if revocation_list:
        for cid, ts in revocation_list.items():
            owner = certificates.get(cid, {}).get("owner", "?")
            crl_rows += f"<tr><td>{cid}</td><td>{owner}</td><td>{ts}</td></tr>"
    else:
        crl_rows = "<tr><td colspan='3'>CRL is empty</td></tr>"

    html = f"""
    <html>
    <head><title>CWE-370</title><style>{CSS}</style></head>
    <body>

    <div style="margin-bottom:20px;">
        <a href="/">Home</a> |
        <a href="/dashboard">Authenticated Dashboard</a> |
        <a href="/safe/dashboard">Safe Dashboard</a> |
        <a href="/logout">Logout</a>
    </div>

    <h2>Certificate Store</h2>
    <div class="box">
        <table>
            <tr><th>Cert ID</th><th>Owner</th><th>Status</th></tr>
            {cert_rows}
        </table>
    </div>

    <h2>Login</h2>
    <div class="box">
        <form method="POST" action="/login">
            <input type="text" name="cert_id" placeholder="e.g. CERT-ALICE-001">
            <input type="submit" value="Login">
        </form>
    </div>

    <h2>Certificate Revocation List (CRL)</h2>
    <div class="box">
        <form method="POST" action="/admin/revoke" style="display:inline-block; margin-right:20px;">
            <input type="text" name="cert_id" placeholder="Cert ID">
            <input type="submit" value="Revoke">
        </form>
        <form method="POST" action="/admin/restore" style="display:inline-block;">
            <input type="text" name="cert_id" placeholder="Cert ID">
            <input type="submit" value="Restore">
        </form>
        <table style="margin-top:10px;">
            <tr><th>Cert ID</th><th>Owner</th><th>Revoked At</th></tr>
            {crl_rows}
        </table>
    </div>

    <h2>Active Sessions</h2>
    <div class="box">
        <table>
            <tr><th>Token</th><th>Owner</th><th>Cert ID</th><th>Login At</th></tr>
            {session_rows}
        </table>
    </div>

    </body>
    </html>
    """
    return html


# ─── POST /login ──────────────────────────────────────────────────────────────

@app.post("/login", response_class=HTMLResponse)
async def login(cert_id: str = Form(...)):
    cert_id = cert_id.strip().upper()

    if cert_id not in certificates:
        return HTMLResponse(f"""
        <html><head><style>{CSS}</style></head><body>
        <div style="margin-bottom:20px;"><a href="/">← Back</a></div>
        <div class="box"><p>Certificate not found: {cert_id}</p></div>
        </body></html>
        """, status_code=400)

    # ── CWE-370: This is the ONLY place revocation is checked ─────────────────
    if is_revoked(cert_id):
        return HTMLResponse(f"""
        <html><head><style>{CSS}</style></head><body>
        <div style="margin-bottom:20px;"><a href="/">← Back</a></div>
        <div class="box"><p>Login denied — {cert_id} is on the Certificate Revocation List.</p></div>
        </body></html>
        """, status_code=403)
    # ──────────────────────────────────────────────────────────────────────────

    # Issue a session token — revocation will NOT be re-checked on subsequent requests
    # (in the vulnerable endpoint). This is the root of CWE-370.
    token = secrets.token_hex(32)
    sessions[token] = {
        "cert_id": cert_id,
        "owner": certificates[cert_id]["owner"],
        "login_at": datetime.datetime.now().strftime("%H:%M:%S"),
    }

    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie("session", token, httponly=True)
    return response


# ─── GET /dashboard — AUTHENTICATED (VULNERABLE) ────────────────────────────

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_authenticated(request: Request):
    token = request.cookies.get("session")

    if not token or token not in sessions:
        return HTMLResponse(f"""
        <html><head><style>{CSS}</style></head><body>
        <div style="margin-bottom:20px;"><a href="/">← Home</a></div>
        <div class="box"><p>No active session. <a href="/">Login first.</a></p></div>
        </body></html>
        """, status_code=401)

    session = sessions[token]
    cert_id = session["cert_id"]

    revoked_notice = ""
    if is_revoked(cert_id):
        revoked_notice = f"""
        <div class="box">
            <p>{cert_id} is on the CRL. Access still granted.</p>
        </div>"""

    html = f"""
    <html>
    <head><title>Authenticated Dashboard — CWE-370</title><style>{CSS}</style></head>
    <body>

    <div style="margin-bottom:20px;">
        <a href="/">Home</a> |
        <a href="/safe/dashboard">Safe Dashboard</a> |
        <a href="/logout">Logout</a>
    </div>

    <h1>Authenticated Dashboard</h1>
    <p>The server has checked your token, you are authenticated.</p>

    {revoked_notice}

    <div class="box">
        <h2>Welcome, {session['owner']}!</h2>
        <p>Certificate: {cert_id}</p>
        <p>Session established at: {session['login_at']}</p>
    </div>

    </body>
    </html>
    """
    return html


# ─── GET /safe/dashboard — SAFE ───────────────────────────────────────────────

@app.get("/safe/dashboard", response_class=HTMLResponse)
async def dashboard_safe(request: Request):
    token = request.cookies.get("session")

    if not token or token not in sessions:
        return HTMLResponse(f"""
        <html><head><style>{CSS}</style></head><body>
        <div style="margin-bottom:20px;"><a href="/">← Home</a></div>
        <div class="box"><p>No active session. <a href="/">Login first.</a></p></div>
        </body></html>
        """, status_code=401)

    session = sessions[token]
    cert_id = session["cert_id"]

    # ── MITIGATION: Re-check the CRL on every single request ──────────────────
    if is_revoked(cert_id):
        return HTMLResponse(f"""
        <html>
        <head><title>Safe Dashboard — CWE-370</title><style>{CSS}</style></head>
        <body>
        <div style="margin-bottom:20px;">
            <a href="/">Home</a> | <a href="/dashboard">Authenticated Dashboard</a>
        </div>
        <h1>Safe Dashboard</h1>
        <div class="box">
            <p>Access denied — {cert_id} was revoked after your session was created.</p>
            <p><a href="/">Return home</a> to restore the certificate or login with a different one.</p>
        </div>
        </body>
        </html>
        """, status_code=403)
    # ──────────────────────────────────────────────────────────────────────────

    html = f"""
    <html>
    <head><title>Safe Dashboard — CWE-370</title><style>{CSS}</style></head>
    <body>

    <div style="margin-bottom:20px;">
        <a href="/">Home</a> |
        <a href="/dashboard">Authenticated Dashboard</a> |
        <a href="/logout">Logout</a>
    </div>

    <h1>Safe Dashboard</h1>
    <p>CRL is re-checked on every request. Revoke the certificate and refresh to see access denied.</p>

    <div class="box">
        <h2>Welcome, {session['owner']}!</h2>
        <p>Certificate: {cert_id}</p>
        <p>Session established at: {session['login_at']}</p>
    </div>

    </body>
    </html>
    """
    return html


# ─── POST /admin/revoke ───────────────────────────────────────────────────────

@app.post("/admin/revoke")
async def revoke_cert(cert_id: str = Form(...)):
    cert_id = cert_id.strip().upper()
    if cert_id in certificates:
        revocation_list[cert_id] = datetime.datetime.now().strftime("%H:%M:%S")
    return RedirectResponse(url="/", status_code=303)


# ─── POST /admin/restore ──────────────────────────────────────────────────────

@app.post("/admin/restore")
async def restore_cert(cert_id: str = Form(...)):
    cert_id = cert_id.strip().upper()
    revocation_list.pop(cert_id, None)
    return RedirectResponse(url="/", status_code=303)


# ─── GET /logout ──────────────────────────────────────────────────────────────

@app.get("/logout")
async def logout(request: Request):
    token = request.cookies.get("session")
    if token:
        sessions.pop(token, None)
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie("session")
    return response
