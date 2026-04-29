"""
CWE-444 — Inconsistent Interpretation of HTTP Requests (HTTP Request Smuggling)

When a front-end proxy and a back-end server disagree on where one HTTP request
ends and the next begins, an attacker can smuggle a prefix of the next request.
This demo simulates both parsers in Python: the vulnerable one honours
Transfer-Encoding: chunked and ignores Content-Length; the safe one rejects any
request that carries both headers, as required by RFC 7230 §3.3.3.
"""

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

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
#result { display: none; margin-top: 10px; }
"""

# ── Navigation ────────────────────────────────────────────────────────────────

NAV = """
<div class="nav">
    <a href="/">Home</a> |
    <button onclick="runDemo('vulnerable')">&#9654; Vulnerable parser</button> |
    <button onclick="runDemo('safe')">&#9654; Safe parser</button>
</div>
"""

# ── JS ────────────────────────────────────────────────────────────────────────

SCRIPT = """
async function runDemo(mode) {
    const el = document.getElementById('result');
    el.style.display = 'block';
    el.textContent = 'Running...';
    try {
        const resp = await fetch('/demo/' + mode);
        const data = await resp.json();
        el.textContent = JSON.stringify(data, null, 2);
    } catch (e) {
        el.textContent = 'Error: ' + e.message;
    }
}
"""

# ── Crafted request ───────────────────────────────────────────────────────────
#
# Content-Length: 46  → proxy reads 46 bytes as body (includes the smuggled line)
# Transfer-Encoding: chunked → backend reads until "0\r\n\r\n", treats the rest
#                              as the start of a new request
#
SMUGGLED_REQUEST = (
    b"POST /data HTTP/1.1\r\n"
    b"Host: victim.com\r\n"
    b"Content-Length: 46\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"\r\n"
    b"0\r\n"
    b"\r\n"
    b"GET /admin HTTP/1.1\r\n"
    b"Host: victim.com\r\n"
    b"\r\n"
)


# ── Parser simulations ────────────────────────────────────────────────────────

def _parse_vulnerable(raw: bytes) -> dict:
    """
    Simulates a back-end that honours Transfer-Encoding: chunked.
    Reads until the chunked terminator '0\\r\\n\\r\\n'; any remaining bytes
    are interpreted as the start of the next HTTP request.
    """
    header_end = raw.find(b"\r\n\r\n")
    body = raw[header_end + 4:] if header_end != -1 else b""

    chunk_terminator = b"0\r\n\r\n"
    term_pos = body.find(chunk_terminator)

    if term_pos == -1:
        return {
            "parser": "Transfer-Encoding (chunked)",
            "requests_seen": 1,
            "request_1_body": body.decode(errors="replace"),
            "smuggled": None,
        }

    first_body = body[: term_pos + len(chunk_terminator)]
    trailing = body[term_pos + len(chunk_terminator):]

    return {
        "parser": "Transfer-Encoding (chunked)",
        "requests_seen": 1 + (1 if trailing.strip() else 0),
        "request_1_body": first_body.decode(errors="replace"),
        "smuggled": trailing.decode(errors="replace") if trailing.strip() else None,
    }


def _parse_safe(raw: bytes) -> dict:
    """
    Rejects any request carrying both Content-Length and Transfer-Encoding.
    RFC 7230 §3.3.3: if both are present, the server MUST reject with 400.
    """
    has_cl = b"Content-Length:" in raw
    has_te = b"Transfer-Encoding:" in raw

    if has_cl and has_te:
        return {
            "accepted": False,
            "reason": (
                "Both Content-Length and Transfer-Encoding present — "
                "request rejected (RFC 7230 §3.3.3)"
            ),
            "smuggled": None,
        }
    return {
        "accepted": True,
        "reason": "No ambiguity — only one framing header present",
        "smuggled": None,
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index():
    raw_display = (
        SMUGGLED_REQUEST.decode(errors="replace")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    return f"""
    <html>
    <head><title>CWE-444</title><style>{CSS}</style></head>
    <body>
    {NAV}

    <h1>CWE-444 &#8212; HTTP Request Smuggling</h1>
    <p>
        When a front-end proxy and a back-end server disagree on where one HTTP request ends,
        an attacker can smuggle bytes into the <em>next</em> request &#8212; bypassing WAFs,
        reaching internal endpoints, or poisoning another user&#8217;s session.
    </p>
    <p>
        The root cause: a single request carries <em>both</em>
        <code>Content-Length</code> and <code>Transfer-Encoding: chunked</code>.
        The proxy uses one header to forward; the back-end uses the other to parse.
        They disagree on where the body ends.
    </p>

    <h2>The Crafted Request</h2>
    <div class="box">
        <pre>{raw_display}</pre>
        <p class="dim">
            <code>Content-Length: 46</code> &#8212; proxy reads 46 bytes as the body
            (this includes the smuggled line).<br>
            <code>Transfer-Encoding: chunked</code> &#8212; back-end reads until
            <code>0\r\n\r\n</code> (end of chunk), then sees
            <code>GET /admin &#8230;</code> as a brand-new request.
        </p>
    </div>

    <h2>Result</h2>
    <div class="box">
        <pre id="result"></pre>
    </div>

    <script>{SCRIPT}</script>
    </body>
    </html>
    """


@app.get("/demo/vulnerable", response_class=JSONResponse)
async def demo_vulnerable():
    result = _parse_vulnerable(SMUGGLED_REQUEST)
    return JSONResponse({
        "mode": "VULNERABLE",
        "description": (
            "Back-end honours Transfer-Encoding. "
            "The smuggled request leaks through as a second request."
        ),
        "cwe": "CWE-444",
        **result,
    })


@app.get("/demo/safe", response_class=JSONResponse)
async def demo_safe():
    result = _parse_safe(SMUGGLED_REQUEST)
    return JSONResponse({
        "mode": "SAFE",
        "description": (
            "Server rejects requests with both Content-Length and "
            "Transfer-Encoding (RFC 7230 §3.3.3). No smuggling possible."
        ),
        "cwe": "CWE-444",
        **result,
    })
