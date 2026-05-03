## CWE-444: Inconsistent Interpretation of HTTP Requests (HTTP Request Smuggling)

When a front-end proxy and a back-end server disagree on where one HTTP request
ends and the next begins, an attacker can smuggle bytes into the next request the
back-end processes - bypassing WAFs, reaching internal endpoints, or poisoning
another user's session.

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

## 3. Architecture

Two servers run in the same process:

| Server | Port | Role |
|--------|------|------|
| FastAPI proxy + UI | :5000 | Serves the page; forwards raw bytes to the backend |
| Raw-socket backend | :5001 | TE-first HTTP parser; logs every request it sees |

The proxy does no rewriting - it opens a plain TCP socket to :5001 and sends
whatever bytes the browser posted verbatim.

---

## 4. Routes

| Route | Method | Purpose |
|-------|--------|---------|
| `/` | GET | UI - textarea editor + backend request log |
| `/send-raw/vulnerable` | POST | Forward raw bytes to :5001 unconditionally |
| `/send-raw/safe` | POST | Reject if both `Content-Length` and `Transfer-Encoding` present (RFC 7230 §3.3.3); otherwise forward |
| `/backend-log` | GET | JSON list of every request the backend parsed |
| `/backend-log/clear` | POST | Clear the log |

---

## 5. Demonstration

### A. Exploit - vulnerable proxy

1. Open DevTools → **Network tab**.
2. Edit the raw HTTP request in the textarea if desired. The default is a
   CL.TE payload:

```
POST /data HTTP/1.1\r\n
Host: victim.com\r\n
Content-Length: 46\r\n
Transfer-Encoding: chunked\r\n
\r\n
0\r\n
\r\n
GET /admin HTTP/1.1\r\n
Host: victim.com\r\n
\r\n
```

3. Click **▶ Send to Vulnerable Proxy**. The browser makes one
   `POST /send-raw/vulnerable` with your bytes as the body.
4. In the Network tab you see **one request** sent by the browser.
5. In the **Backend Request Log** on the page you see **two requests**
   the backend parsed from that single TCP connection:

```
conn=1  seq=1  POST /data HTTP/1.1      framing: Transfer-Encoding: chunked
conn=1  seq=2  GET /admin HTTP/1.1      framing: none (no body)   ← SMUGGLED
```

`seq=2` is the smuggled request - the back-end processed a `GET /admin`
that was never issued directly by the browser.

### B. Safe proxy

1. Click **▶ Send to Safe Proxy** with the same payload.
2. The proxy returns HTTP 400 before forwarding anything:

```json
{
  "mode": "SAFE",
  "accepted": false,
  "reason": "Both Content-Length and Transfer-Encoding present - request rejected before forwarding (RFC 7230 §3.3.3)"
}
```

Nothing reaches :5001. The backend log stays empty.

---

## 6. The Vulnerability

**Why the CL.TE payload works:**

The proxy uses `Content-Length: 46` to determine how many bytes to forward as
the body. 46 bytes covers the chunked terminator (`0\r\n\r\n`) *and* the
beginning of the smuggled request (`GET /admin HTTP/1.1\r\nHost: victim.com\r\n\r\n`).
The proxy sees one request and forwards everything.

The back-end uses `Transfer-Encoding: chunked` as priority. It reads the body
until the zero-length chunk terminator (`0\r\n\r\n`), considers the first
request done, and then reads the remaining bytes as the start of the next
request on the persistent connection - the smuggled `GET /admin`.

**Vulnerable - backend uses TE, ignores CL:**
```python
# Reads until "0\r\n\r\n"; remaining bytes become the next request.
term = after_headers.find(b"0\r\n\r\n")
remaining = after_headers[term + 5:]   # ← this is the smuggled request
```

**Safe - proxy rejects on ambiguity (RFC 7230 §3.3.3):**
```python
if has_cl and has_te:
    return 400  # reject before forwarding - no ambiguity reaches the backend
```

---

## 7. Why It Matters

- Attackers can bypass front-end WAFs by smuggling a request the WAF never inspects.
- A smuggled prefix poisons the next legitimate user's request on the same backend connection - enabling session hijacking or response splitting.
- Real CVEs exist in HaProxy, Nginx, Apache, and AWS ALB for CL/TE ambiguity.
- Fix: at every hop, if both headers are present either drop `Content-Length` or
  reject with 400. Using HTTP/2 end-to-end eliminates the framing ambiguity entirely.
