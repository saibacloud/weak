"""
CWE-444 - Inconsistent Interpretation of HTTP Requests (HTTP Request Smuggling)

Two servers run in this process:
  :5000  FastAPI proxy + UI
  :5001  Raw-socket backend - TE-first parser, logs every request it sees

The user edits the raw HTTP bytes in the browser, POSTs them to the proxy via
/send-raw/vulnerable (or /send-raw/safe), and the proxy forwards them verbatim
over a raw TCP socket to the backend.

Network tab: one POST to /send-raw/vulnerable
Backend log: two requests processed - the smuggled GET /admin is seq 2.

Safe path: the proxy rejects any request carrying both Content-Length and
Transfer-Encoding before forwarding (RFC 7230 §3.3.3).
"""

import asyncio
import datetime
import socket
import threading
from collections import deque

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI()

# ── Shared backend request log ────────────────────────────────────────────────

_log: deque[dict] = deque(maxlen=100)
_log_lock = threading.Lock()
_conn_counter = 0
_conn_lock = threading.Lock()

BACKEND_HOST = "127.0.0.1"
BACKEND_PORT = 5001

# ── Default smuggled payload (CL.TE variant) ──────────────────────────────────
#
# Front-end proxy: uses Content-Length: 46 to determine where the body ends.
# Back-end server: uses Transfer-Encoding: chunked, reads until 0\r\n\r\n.
#
# The proxy forwards the entire 46-byte body to the backend as one request.
# The backend parses the chunked body (0\r\n\r\n = empty chunk = end), then
# sees the remaining bytes as the start of a brand-new request.

DEFAULT_PAYLOAD = (
    "POST /data HTTP/1.1\r\n"
    "Host: victim.com\r\n"
    "Content-Length: 46\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "GET /admin HTTP/1.1\r\n"
    "Host: victim.com\r\n"
    "\r\n"
)

# ── Backend: raw-socket HTTP server (TE-first parser) ────────────────────────


def _parse_te_first(data: bytes) -> list[dict]:
    """
    Parse as many HTTP/1.1 requests as possible from `data`.
    Transfer-Encoding takes priority over Content-Length when both are present.
    """
    requests: list[dict] = []
    remaining = data

    while remaining:
        header_end = remaining.find(b"\r\n\r\n")
        if header_end == -1:
            break

        raw_headers = remaining[:header_end]
        after_headers = remaining[header_end + 4 :]

        lines = raw_headers.split(b"\r\n")
        if not lines or not lines[0]:
            break

        request_line = lines[0].decode(errors="replace")
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if b":" in line:
                k, _, v = line.partition(b":")
                headers[k.strip().decode(errors="replace").lower()] = v.strip().decode(
                    errors="replace"
                )

        te = headers.get("transfer-encoding", "")
        cl_raw = headers.get("content-length")

        if "chunked" in te:
            term = after_headers.find(b"0\r\n\r\n")
            if term == -1:
                break
            chunk_body = after_headers[: term + 5]
            remaining = after_headers[term + 5 :]
            requests.append(
                {
                    "request_line": request_line,
                    "framing": "Transfer-Encoding: chunked",
                    "body_repr": repr(chunk_body.decode(errors="replace")),
                }
            )
        elif cl_raw is not None:
            try:
                cl = int(cl_raw)
            except ValueError:
                break
            requests.append(
                {
                    "request_line": request_line,
                    "framing": f"Content-Length: {cl}",
                    "body_repr": repr(after_headers[:cl].decode(errors="replace")),
                }
            )
            remaining = after_headers[cl:]
        else:
            requests.append(
                {
                    "request_line": request_line,
                    "framing": "none (no body)",
                    "body_repr": "''",
                }
            )
            remaining = b""

    return requests


def _backend_handle(conn: socket.socket, conn_id: int) -> None:
    try:
        conn.settimeout(0.4)
        data = b""
        while True:
            try:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            except (socket.timeout, OSError):
                break

        parsed = _parse_te_first(data)
        ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

        with _log_lock:
            for i, req in enumerate(parsed, start=1):
                _log.appendleft(
                    {
                        "conn_id": conn_id,
                        "time": ts,
                        "seq": i,
                        "request_line": req["request_line"],
                        "framing": req["framing"],
                        "body_repr": req["body_repr"],
                        "smuggled": i > 1,
                    }
                )

        resp = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 15\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            b'{"status":"ok"}'
        )
        conn.sendall(resp)
    except Exception:
        pass
    finally:
        conn.close()


def _backend_server() -> None:
    global _conn_counter
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((BACKEND_HOST, BACKEND_PORT))
    sock.listen(20)
    while True:
        try:
            conn, _ = sock.accept()
            with _conn_lock:
                _conn_counter += 1
                cid = _conn_counter
            threading.Thread(
                target=_backend_handle, args=(conn, cid), daemon=True
            ).start()
        except Exception:
            break


threading.Thread(target=_backend_server, daemon=True).start()


# ── Proxy helpers ─────────────────────────────────────────────────────────────


def _forward(raw: bytes) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((BACKEND_HOST, BACKEND_PORT))
        s.sendall(raw)
        s.settimeout(1.0)
        resp = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
            except socket.timeout:
                break
    return resp.decode(errors="replace")


def _has_cl_and_te(raw: bytes) -> bool:
    header_end = raw.find(b"\r\n\r\n")
    headers = raw[:header_end] if header_end != -1 else raw
    has_cl = any(
        line.lower().startswith(b"content-length:") for line in headers.split(b"\r\n")
    )
    has_te = any(
        line.lower().startswith(b"transfer-encoding:")
        for line in headers.split(b"\r\n")
    )
    return has_cl and has_te


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
         border: 1px solid #999; background: #ddd; border-radius: 2px; margin-right: 4px; }
button:hover { background: #ccc; }
textarea { font-family: monospace; font-size: 0.85em; width: 100%; padding: 8px;
           background: #f5f5f5; border: 1px solid #bbb; resize: vertical; }
tr.smuggled td { background: #e0e0e0; font-weight: bold; }
#proxy-result { display: none; margin-top: 10px; }
"""

NAV = """
<div class="nav">
    <a href="/">Home</a> |
    <button onclick="send('vulnerable')">&#9654; Send to Vulnerable Proxy</button>
    <button onclick="send('safe')">&#9654; Send to Safe Proxy</button>
    <button onclick="clearLog()" style="float:right">&#215; Clear Log</button>
</div>
"""

SCRIPT = """
async function send(mode) {
    const raw = document.getElementById('payload').value;
    // Normalize: collapse any existing CRLF first, then expand all LF to CRLF
    const normalized = raw.replace(/\\r\\n/g, '\\n').replace(/\\n/g, '\\r\\n');
    const el = document.getElementById('proxy-result');
    el.style.display = 'block';
    el.textContent = 'Forwarding…';
    try {
        const resp = await fetch('/send-raw/' + mode, {
            method: 'POST',
            headers: { 'Content-Type': 'text/plain' },
            body: normalized
        });
        const data = await resp.json();
        el.textContent = JSON.stringify(data, null, 2);
    } catch (e) {
        el.textContent = 'Error: ' + e.message;
    }
    await refreshLog();
}

async function refreshLog() {
    try {
        const resp = await fetch('/backend-log');
        const data = await resp.json();
        const tbody = document.getElementById('log-body');
        tbody.innerHTML = '';
        if (!data.entries.length) {
            tbody.innerHTML = '<tr><td colspan="5">No entries yet.</td></tr>';
            return;
        }
        for (const e of data.entries) {
            const cls = e.smuggled ? 'smuggled' : '';
            const badge = e.smuggled
                ? '<span class="tag-vuln">&#9888; SMUGGLED</span>'
                : '';
            tbody.innerHTML += `<tr class="${cls}">
                <td>${esc(e.time)}</td>
                <td>#${e.conn_id}</td>
                <td>${e.seq} ${badge}</td>
                <td>${esc(e.request_line)}</td>
                <td>${esc(e.framing)}</td>
            </tr>`;
        }
    } catch (_) {}
}

async function clearLog() {
    await fetch('/backend-log/clear', { method: 'POST' });
    await refreshLog();
}

function esc(s) {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

refreshLog();
"""


# ── Routes ────────────────────────────────────────────────────────────────────


@app.get("/", response_class=HTMLResponse)
async def index():
    # Render the default payload for the textarea (CRLF → LF for display)
    display_payload = DEFAULT_PAYLOAD.replace("\r\n", "\n")

    return f"""<!DOCTYPE html>
<html>
<head><title>CWE-444 - HTTP Request Smuggling</title><style>{CSS}</style></head>
<body>
{NAV}

<h1>CWE-444 - HTTP Request Smuggling</h1>
<p>
  When a front-end proxy and a back-end server disagree on where one HTTP request
  ends, an attacker can smuggle bytes into the <em>next</em> request the back-end
  processes - bypassing WAFs, reaching internal endpoints, or poisoning
  another user&#8217;s session.
</p>
<p>
  Root cause: a single request carries both <code>Content-Length</code> and
  <code>Transfer-Encoding: chunked</code>. The proxy uses CL to determine how
  many bytes to forward; the back-end uses TE to parse the body. They disagree
  on where the body ends.
</p>



<h2>Craft Your Request</h2>
<div class="box">
  <textarea id="payload" rows="13">{display_payload}</textarea>
  <p class="dim" style="margin-top:6px;">
    Line endings are normalized to CRLF before sending. The
    <code>Content-Length</code> in the default payload is calibrated to 46:
    exactly the bytes from <code>0&#92;r&#92;n</code> through the trailing
    <code>&#92;r&#92;n</code> of the smuggled request - just enough for
    the proxy to forward everything while the back-end&#8217;s TE parser stops
    at the chunk terminator.
  </p>
</div>

<h2>Proxy Response</h2>
<div class="box" id="proxy-result"></div>

<h2>Backend Request Log <span class="dim">(port :5001, TE-first parser)</span></h2>
<div class="box">
  <p class="dim">
    Every HTTP request the back-end parsed from incoming TCP connections.
    Smuggled requests (seq &gt; 1 on the same connection) are highlighted.
  </p>
  <table>
    <thead>
      <tr><th>Time</th><th>Conn</th><th>Seq</th><th>Request Line</th><th>Framing used</th></tr>
    </thead>
    <tbody id="log-body">
      <tr><td colspan="5">No entries yet.</td></tr>
    </tbody>
  </table>
</div>

<script>{SCRIPT}</script>
</body>
</html>"""


@app.post("/send-raw/vulnerable", response_class=JSONResponse)
async def send_raw_vulnerable(request: Request):
    raw = await request.body()
    loop = asyncio.get_event_loop()
    try:
        backend_resp = await loop.run_in_executor(None, _forward, raw)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=502)
    return JSONResponse(
        {
            "mode": "VULNERABLE",
            "bytes_forwarded": len(raw),
            "backend_raw_response": backend_resp,
            "note": "Check the Backend Request Log - the back-end may have parsed more than one request from this connection.",
        }
    )


@app.post("/send-raw/safe", response_class=JSONResponse)
async def send_raw_safe(request: Request):
    raw = await request.body()
    if _has_cl_and_te(raw):
        return JSONResponse(
            {
                "mode": "SAFE",
                "accepted": False,
                "reason": (
                    "Both Content-Length and Transfer-Encoding present - "
                    "request rejected before forwarding (RFC 7230 §3.3.3)"
                ),
            },
            status_code=400,
        )
    loop = asyncio.get_event_loop()
    try:
        backend_resp = await loop.run_in_executor(None, _forward, raw)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=502)
    return JSONResponse(
        {
            "mode": "SAFE",
            "accepted": True,
            "bytes_forwarded": len(raw),
            "backend_raw_response": backend_resp,
        }
    )


@app.get("/backend-log", response_class=JSONResponse)
async def get_backend_log():
    with _log_lock:
        entries = list(_log)
    return JSONResponse({"entries": entries})


@app.post("/backend-log/clear", response_class=JSONResponse)
async def clear_backend_log():
    with _log_lock:
        _log.clear()
    return JSONResponse({"cleared": True})


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=5000)
