## Confused Deputy / SSRF Demonstration

This app demonstrates **CWE-441: Unintended Proxy or Intermediary (Confused Deputy)** using **SSRF**.

There's a link-preview service that fetches URLs on your behalf. That server sits inside the network and can reach things that you as a user, cannot. If it'll fetch *anything* you tell it to, you can point it at internal services and get the response back, even though you'd normally have no route there.

---

## 1. Install
```bash
pip install -r requirements.txt
```

## 2. Start Demo
Open two terminals

**Terminal 1 — the internal service** (the target):
```bash
uvicorn internal:app --port 8001
```

**Terminal 2 — the public app** (the confused deputy):
```bash
uvicorn main:app --reload --port 5000
```

Open browser to:
```
http://127.0.0.1:5000
```

---

## 3. Config

### Routes
| Route | Method | Purpose |
|-------|--------|---------|
| `/` | GET | Vulnerable fetcher |
| `/fetch` | POST | Fetches whatever URL you give it, no questions asked |
| `/safe` | GET | Safe fetcher |
| `/safe/fetch` | POST | Validates the destination before doing anything |

### The Setup
```
+-------------------------------------------------+
|                  FIREWALL                       |
|   External traffic --> port 5000 only           |
|   port 8001 is blocked to external clients      |
+-------------------------------------------------+

[Your Browser]  --> can reach: localhost:5000   (the deputy)
                X   can't reach: localhost:8001  (internal service)

[Server :5000]  --> can reach: localhost:8001   <-- the deputy's privilege
```

Port 8001 is the "internal" service — in real life this would be on a separate box behind a firewall. For this demo everything's on localhost, but the mechanics are identical.

---

## 4. Demonstration

### A. Vulnerable Fetcher — `/`

**Step 1 — normal use:**
```
https://httpbin.org/get
```
Server fetches it and returns the response. This is what link preview tools, webhook testers, screenshot services etc. do normally.

**Step 2 — the attack:**
```
http://localhost:8001/admin
```
You can't hit port 8001 from your browser. The server can. So you give the server that URL, it fetches the internal config using its own network access, and hands the response straight back to you.

That's the confused deputy. It's not a bug in the internal service — the internal service is *supposed* to trust requests coming from inside the network. The problem is the public server will carry your request to anywhere without checking if it should.

**Step 3 — cloud metadata:**
```
http://169.254.169.254/latest/meta-data/
```
On AWS, GCP, and Azure, the instance metadata service lives at that link-local address. Only the server can reach it. Ask the confused deputy to fetch it and you'll get IAM tokens, credentials, and instance details.

---

### B. Safe Fetcher — `/safe`

Try the same payloads. Before making any request, the server resolves the hostname to an IP and checks whether it falls into a blocked range:
- Loopback (`127.x.x.x`, `::1`)
- Private (`10/8`, `172.16/12`, `192.168/16`)
- Link-local (`169.254/16` — cloud metadata)
- Anything else IANA-reserved

If it does, the request is blocked before the server touches the network.

---

## 5. Notes

**The attack (`/fetch`):**

***You're not exploiting a bug in the internal service. The internal service is working exactly as designed — it trusts requests from inside the network. The bug is that the public server will carry out any fetch you ask for without checking where it's going.***

```python
async with httpx.AsyncClient(follow_redirects=True, timeout=5.0) as client:
    resp = await client.get(url)
```

No destination check. Whatever URL comes in, the server fetches it using its own network position and returns the response.

**The fix (`/safe/fetch`):**

***Resolve the hostname to an IP before connecting, then check it against blocked ranges. If it resolves to something internal, the server refuses to act — the request never leaves.***

```python
ip_str = socket.gethostbyname(hostname)
addr = ipaddress.ip_address(ip_str)

if addr.is_loopback or addr.is_private or addr.is_link_local or addr.is_reserved:
    # block it
```

This stops you from steering the server's privileged network access into its own internal network.

**Classic analogy:** A secretary (the deputy) has a master key to the whole building. A visitor says "can you fetch my coat from room 42?" The secretary unlocks room 42 without checking if the visitor is supposed to be in room 42. The visitor didn't have the key — but they didn't need to. They just needed the secretary.

---

## 6. The Fix

```python
# Resolve the real absolute path — symlinks, .. components, all of it
resolved = os.path.realpath(os.path.join(DOCS_DIR, filename))
allowed_base = os.path.realpath(DOCS_DIR)

# The deputy only acts if the resolved path is inside the allowed base
if not resolved.startswith(allowed_base + os.sep):
    return "Access denied."
```

`os.path.realpath()` collapses `..` and symlinks before we check, so you can't sneak past the prefix check. The deputy validates the request against its own scope before acting, not against what the caller claims.
