## CWE-370: Missing Check for Certificate Revocation After Initial Check

This app demonstrates **CWE-370**, where a certificate's revocation status is only validated
**at login time** — and never re-checked on subsequent requests within the same session.

1. **Vulnerable `/dashboard`** — trusts the session token alone; the CRL is never consulted again
2. **Safe `/safe/dashboard`** — re-validates the certificate against the CRL on **every request**

---

## 1. Install in Venv
```bash
source .venv/bin/activate.fish

pip install -r requirements.txt
```

## 2. Start Demo
```bash
uvicorn main:app --reload --port 5000
```
Open browser to:
```
http://127.0.0.1:5000
```

---

## 3. Config

### Data Stores
- **`certificates`**: Simulated PKI store — three pre-issued certs (Alice, Bob, Carol)
- **`revocation_list`**: In-memory CRL — cert IDs mapped to revocation timestamp
- **`sessions`**: Active sessions — token mapped to `{ cert_id, owner, login_at }`

The vulnerability lives in the gap between session creation and subsequent requests:
the CRL is checked when a session is born but never again for the life of that session.

### Routes
| Route | Method | Purpose |
|-------|--------|---------|
| `/` | GET | Home — shows cert store, CRL, active sessions, login + admin panel |
| `/login` | POST | Authenticates with a cert ID — **only CRL check happens here** |
| `/dashboard` | GET | **Vulnerable** — grants access based on session alone, no CRL re-check |
| `/safe/dashboard` | GET | **Safe** — re-checks CRL on every request before granting access |
| `/admin/revoke` | POST | Adds a cert to the CRL (simulates CA revocation) |
| `/admin/restore` | POST | Removes a cert from the CRL (resets for demo) |
| `/logout` | GET | Clears the session cookie and removes the session |

---

## 4. Demonstration

### Step 1 — Login with a valid certificate
Go to `http://127.0.0.1:5000`, type `CERT-ALICE-001` in the login form, and submit.

The app checks the CRL — it's empty — and issues a session cookie. You land on `/dashboard`
which shows "Welcome, Alice!".

### Step 2 — Verify the safe dashboard also works
Navigate to `http://127.0.0.1:5000/safe/dashboard`.

Alice's cert is still valid, so both dashboards grant access. So far, identical behaviour.

### Step 3 — Revoke the certificate mid-session
Go back to `http://127.0.0.1:5000`, type `CERT-ALICE-001` in the **Revoke** field, and submit.

The home page now shows:
- Alice's cert as `✗ REVOKED` in the Certificate Store
- Alice's active session flagged: *"cert revoked — session still alive (vuln mode)!"*

### Step 4 — Hit the vulnerable dashboard
Navigate to `http://127.0.0.1:5000/dashboard`.

You still see "Welcome, Alice!" — but now with an orange warning banner confirming the cert is on
the CRL and the endpoint simply doesn't care. **Access is granted despite the revocation.**

### Step 5 — Hit the safe dashboard
Navigate to `http://127.0.0.1:5000/safe/dashboard`.

```
✗ Access Denied — CERT-ALICE-001 has been revoked since your session was created.
```

The safe endpoint catches the revocation immediately and returns **403 Forbidden**.

---

## 5. The Vulnerability in Code

**Vulnerable endpoint** — only checks session dict:
```python
# /dashboard
if not token or token not in sessions:
    return 401

# Cert revocation status is NEVER consulted here
session = sessions[token]
return render_dashboard(session)
```

**Safe endpoint** — re-checks the CRL on every request:
```python
# /safe/dashboard
if not token or token not in sessions:
    return 401

session = sessions[token]
cert_id = session["cert_id"]

# ✓ Re-check revocation on every request
if is_revoked(cert_id):
    return 403  # Blocked even with a valid session token

return render_dashboard(session)
```

---

## 6. Why This Matters

A certificate may be revoked because:
- The private key was compromised
- The user's credentials or role were terminated
- The issuing CA detected misuse

If the application only checks revocation once, an attacker with a **stolen session** from a
revoked certificate — or a legitimate user whose access was terminated — **keeps full access**
for the lifetime of the session. The CRL update never propagates through.

Real-world systems mitigate this with:
- **CRL re-check on every privileged request**
- **Short session lifetimes** paired with re-authentication
- **OCSP stapling** — server proves cert validity to the client at each TLS handshake
- **OCSP Must-Staple** — client refuses connection if fresh proof is absent
