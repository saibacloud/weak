## CWE-444: Inconsistent Interpretation of HTTP Requests (HTTP Request Smuggling)

When a front-end proxy and a back-end server disagree on where one HTTP request
ends and the next begins, an attacker can smuggle bytes into the next request —
bypassing WAFs, reaching internal endpoints, or poisoning another user's session.
This demo simulates both the vulnerable parsing behaviour (honouring
Transfer-Encoding: chunked and ignoring Content-Length) and the safe behaviour
(rejecting any request that carries both headers, per RFC 7230 §3.3.3).

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
| `main.py` | FastAPI app — crafted smuggle request, both parser simulations, home page |

### Routes
| Route | Method | Purpose |
|-------|--------|---------|
| `/` | GET | Home — shows the crafted request and demo buttons |
| `/demo/vulnerable` | GET | TE-honouring parser — smuggled request visible in response |
| `/demo/safe` | GET | Safe parser — rejects the ambiguous request with an explanation |

---

## 4. Demonstration

### A. Vulnerable parser — `/demo/vulnerable`

1. Open DevTools → **Network tab**.
2. Click **"▶ Vulnerable parser"** on the home page.
3. In the Network tab, inspect the JSON response. You will see:

```json
{
  "mode": "VULNERABLE",
  "parser": "Transfer-Encoding (chunked)",
  "requests_seen": 2,
  "request_1_body": "0\r\n\r\n",
  "smuggled": "GET /admin HTTP/1.1\r\nHost: victim.com\r\n\r\n"
}
```

`requests_seen: 2` — the back-end interpreted the trailing bytes as a second, independent
request: `GET /admin HTTP/1.1`. The attacker reached an internal endpoint without issuing
that request directly.

### B. Safe parser — `/demo/safe`

1. Click **"▶ Safe parser"** on the home page.
2. The result shows:

```json
{
  "mode": "SAFE",
  "accepted": false,
  "reason": "Both Content-Length and Transfer-Encoding present — request rejected (RFC 7230 §3.3.3)",
  "smuggled": null
}
```

The server refused to process the request before any parsing happened.
No smuggling is possible because the ambiguous request is rejected outright.

---

## 5. The Vulnerability in Code

**Vulnerable — back-end honours Transfer-Encoding, ignores Content-Length:**
```python
# Reads until "0\r\n\r\n" (end of chunked body).
# Everything after that terminator is treated as the next request.
term_pos = body.find(b"0\r\n\r\n")
trailing = body[term_pos + 5:]  # ← this is the smuggled request
```

**Safe — reject on ambiguity (RFC 7230 §3.3.3):**
```python
# If both headers are present, return 400 before forwarding.
if has_cl and has_te:
    return {"accepted": False, "reason": "Both headers present — rejected"}
```

---

## 6. Why It Matters

- Attackers can bypass front-end WAFs and auth proxies by smuggling a request that only the back-end sees — the WAF inspects one request, the back-end processes two
- A smuggled prefix poisons the next user's request: their legitimate request arrives at the back-end prefixed with attacker-controlled bytes, enabling session hijacking or response splitting
- Cloud load balancers have real CVEs here: HaProxy, Nginx, Apache, and AWS ALB have all shipped fixes for CL/TE ambiguity in production
- Real-world fix: normalise headers at every hop; if both are present, drop `Content-Length` or reject with 400; use HTTP/2 end-to-end (which has no request framing ambiguity)
