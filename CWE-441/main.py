# CWE-441: Confused Deputy / SSRF demo.
# A link-preview service that will fetch any URL you give it — including internal ones.
# The server lives inside the network, you don't. That's the whole problem.

from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse
import httpx
import ipaddress
import socket
from urllib.parse import urlparse

app = FastAPI()

CSS = """
body         { font-family: sans-serif; padding: 20px; max-width: 860px; margin: auto; }
h1           { margin-top: 0; }
.box         { border: 1px solid #ccc; padding: 14px; margin: 12px 0;
               background: #f4f4f4; white-space: pre-wrap; font-family: monospace;
               overflow-x: auto; }
.warn        { background: #fff3cd; border: 1px solid #ffc107; padding: 10px; margin: 12px 0; }
.safe-badge  { background: #d4edda; border: 1px solid #28a745;
               padding: 8px 14px; display: inline-block; margin-bottom: 14px; }
.deny        { background: #f8d7da; border: 1px solid #dc3545; padding: 12px; margin: 12px 0; }
input[type=text] { width: 440px; padding: 6px; font-size: 14px; }
button       { padding: 6px 14px; font-size: 14px; }
nav          { margin-bottom: 22px; font-size: 15px; }
code         { background: #eee; padding: 1px 4px; border-radius: 3px; }
"""

NAV = """
<nav>
  <a href="/">&#9888; Vulnerable Fetcher</a> &nbsp;|&nbsp;
  <a href="/safe">&#10003; Safe Fetcher</a>
</nav>
"""

TOPOLOGY = """
<pre style="background:#1e1e1e;color:#ddd;padding:14px;border-radius:6px;font-size:13px;overflow-x:auto">
  +-------------------------------------------------+
  |                  FIREWALL                       |
  |   External traffic --> port 5000 only           |
  |   port 8001 is blocked to external clients      |
  +-------------------------------------------------+

  [Your Browser]  --> can reach: localhost:5000  (public app / the deputy)
                  X   can't reach: localhost:8001 (internal service)

  [Server :5000]  --> can reach: localhost:8001  &lt;-- the deputy's privilege
</pre>
"""


# --- Vulnerable version ---

@app.get("/", response_class=HTMLResponse)
async def index():
    return f"""
    <html>
    <head><title>URL Fetcher (Vulnerable)</title><style>{CSS}</style></head>
    <body>
      {NAV}
      <h1>URL Fetcher &#8212; Link Preview Service</h1>
      <div class="warn">
        <strong>Demo note:</strong> This is the <strong>vulnerable</strong> version.
        The server (the deputy) fetches whatever URL you supply, using its own
        network identity. It has access to internal services you cannot reach.
      </div>

      <h3>Network topology:</h3>
      {TOPOLOGY}

      <h3>Fetch a URL:</h3>
      <form method="POST" action="/fetch">
        <input type="text" name="url" placeholder="https://example.com" required>
        &nbsp;<button type="submit">Fetch</button>
      </form>

      <p>
        <strong>Step 1 &#8212; normal use:</strong>
        <code>https://httpbin.org/get</code><br>
        The server fetches an external URL and returns the result. Expected behaviour.
      </p>
      <p>
        <strong>Step 2 &#8212; the attack:</strong>
        <code>http://localhost:8001/admin</code><br>
        You cannot reach port 8001 directly (it is "firewalled"). But the server can.
        Submit that URL and the <em>server</em> fetches the internal secrets using its
        own trusted network position, then hands them to you.
      </p>
      <p>
        <strong>Step 3 &#8212; cloud metadata variant:</strong>
        <code>http://169.254.169.254/latest/meta-data/</code><br>
        On AWS/GCP/Azure, the instance metadata service lives at this link-local address.
        Only the server can reach it &#8212; you cannot &#8212; but the confused deputy
        will fetch cloud credentials on your behalf if you ask it to.
      </p>
    </body>
    </html>
    """


@app.post("/fetch", response_class=HTMLResponse)
async def fetch_vuln(url: str = Form(...)):
    # Vulnerability: take whatever URL the user gives us and fetch it using the server's
    # own network connection. No check on where it's pointing.
    # The server can reach internal services the browser can't — so if you aim it there, it goes.
    result_html = ""
    error_html = ""
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=5.0) as client:
            resp = await client.get(url)
        content = resp.text[:6000]
        result_html = f"""
        <div class="box">
<strong>URL fetched by the deputy:</strong> {url}
<strong>HTTP status:</strong>               {resp.status_code}
<strong>Content-Type:</strong>              {resp.headers.get("content-type", "&#8212;")}
&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;
{content}
        </div>"""
    except Exception as e:
        error_html = f"<div class='box'>Error: {e}</div>"

    return f"""
    <html>
    <head><title>URL Fetcher (Vulnerable)</title><style>{CSS}</style></head>
    <body>
      {NAV}
      <h1>URL Fetcher &#8212; Result</h1>
      <div class="warn">
        Vulnerable version &#8212; the deputy fetched this URL using its own network
        identity, with no validation of the destination.
      </div>
      {result_html}{error_html}
      <a href="/">&#8592; Back</a>
    </body>
    </html>
    """


# --- Safe version ---

@app.get("/safe", response_class=HTMLResponse)
async def safe_index():
    return f"""
    <html>
    <head><title>URL Fetcher (Safe)</title><style>{CSS}</style></head>
    <body>
      {NAV}
      <h1>URL Fetcher &#8212; Safe Version</h1>
      <div class="safe-badge">&#10003; Loopback &#183; private &#183; link-local &#183; reserved addresses blocked</div>

      <h3>Fetch a URL:</h3>
      <form method="POST" action="/safe/fetch">
        <input type="text" name="url" placeholder="https://example.com" required>
        &nbsp;<button type="submit">Fetch</button>
      </form>

      <p>
        Try <code>http://localhost:8001/admin</code> &#8212; the server will resolve the
        hostname to a loopback address and block the request <em>before the deputy
        ever uses its network access</em>.
      </p>
      <p>
        Try <code>http://169.254.169.254/latest/meta-data/</code> &#8212; blocked as
        link-local (the cloud metadata range).
      </p>
    </body>
    </html>
    """


def _validate_url(url: str) -> tuple[bool, str]:
    # Resolve the hostname to an IP first, then check if it's in a range we don't want
    # the server fetching from — loopback, private, link-local, reserved.
    # Resolving before connecting also helps with basic DNS rebinding.
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False, "Only http and https schemes are permitted."

        hostname = parsed.hostname
        if not hostname:
            return False, "Could not parse a hostname from the URL."

        # Resolve DNS first — this catches 'localhost', short hostnames, aliases, etc.
        ip_str = socket.gethostbyname(hostname)
        addr = ipaddress.ip_address(ip_str)

        if addr.is_loopback:
            return False, (
                f"Blocked: <code>{hostname}</code> resolves to loopback address "
                f"<code>{ip_str}</code>. The deputy cannot forward requests to itself."
            )
        if addr.is_private:
            return False, (
                f"Blocked: <code>{hostname}</code> resolves to private address "
                f"<code>{ip_str}</code>. Access to the internal network is not permitted."
            )
        if addr.is_link_local:
            return False, (
                f"Blocked: <code>{hostname}</code> resolves to link-local address "
                f"<code>{ip_str}</code> (cloud instance metadata range &#8212; access denied)."
            )
        if addr.is_reserved:
            return False, (
                f"Blocked: <code>{hostname}</code> resolves to reserved address "
                f"<code>{ip_str}</code>."
            )

        return True, ""

    except socket.gaierror:
        return False, f"Could not resolve hostname in URL: <code>{url}</code>"
    except Exception as e:
        return False, f"Validation error: {e}"


@app.post("/safe/fetch", response_class=HTMLResponse)
async def fetch_safe(url: str = Form(...)):
    # Before doing anything, validate the destination.
    # If the resolved IP is internal/reserved, we refuse to fetch it.
    ok, reason = _validate_url(url)

    if not ok:
        return f"""
        <html>
        <head><title>URL Fetcher (Safe)</title><style>{CSS}</style></head>
        <body>
          {NAV}
          <h1>URL Fetcher &#8212; Safe Version</h1>
          <div class="safe-badge">&#10003; Loopback &#183; private &#183; link-local &#183; reserved addresses blocked</div>
          <div class="deny">
            <strong>Request blocked &#8212; the deputy did not act.</strong><br><br>
            {reason}
          </div>
          <a href="/safe">&#8592; Back</a>
        </body>
        </html>
        """

    result_html = ""
    error_html = ""
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=5.0) as client:
            resp = await client.get(url)
        content = resp.text[:6000]
        result_html = f"""
        <div class="box">
<strong>URL fetched by the deputy:</strong> {url}
<strong>HTTP status:</strong>               {resp.status_code}
<strong>Content-Type:</strong>              {resp.headers.get("content-type", "&#8212;")}
&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;&#8213;
{content}
        </div>"""
    except Exception as e:
        error_html = f"<div class='box'>Error: {e}</div>"

    return f"""
    <html>
    <head><title>URL Fetcher (Safe)</title><style>{CSS}</style></head>
    <body>
      {NAV}
      <h1>URL Fetcher &#8212; Safe Version</h1>
      <div class="safe-badge">&#10003; Loopback &#183; private &#183; link-local &#183; reserved addresses blocked</div>
      {result_html}{error_html}
      <a href="/safe">&#8592; Back</a>
    </body>
    </html>
    """
