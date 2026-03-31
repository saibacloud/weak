## Confused Deputy Vulnerability Demonstration

This app demonstrates **CWE-441: Unintended Proxy or Intermediary ("Confused Deputy")** — where a privileged server acts on behalf of an unprivileged client without checking whether the client should actually be allowed to make that request.

---

## 1. Install
Install the required libraries:
```bash
pip install -r requirements.txt
```

## 2. Start Demo
Open terminal, navigate to project folder, run:
```bash
uvicorn main:app --reload --port 5000
```
Open browser to:
```
http://127.0.0.1:5000
```

---

## 3. Config

### Folder Layout
```
CWE-441/
├── main.py
├── requirements.txt
├── docs/            ← files the portal is supposed to serve
│   ├── readme.txt
│   ├── notice.txt
│   └── changelog.txt
└── secrets/         ← files the portal should never touch
    └── config.env
```

### Routes
| Route | Method | Purpose |
|-------|--------|---------|
| `/` | GET | Vulnerable document portal |
| `/read` | POST | Vulnerable file read — no path validation |
| `/safe` | GET | Safe document portal |
| `/safe/read` | POST | Safe file read — path validated before the deputy acts |

---

## 4. Demonstration

### The Setup

There's a document portal. The server process (the **deputy**) has read access to the filesystem. You, the browser client, do not — you're just submitting a form.

When you ask the portal to read a file, the deputy reads it *using its own OS-level privileges* and hands you the result. That's the deputy pattern: a privileged intermediary acting on behalf of a less-privileged caller.

The vulnerability is that the deputy never asks: *"Is this caller actually allowed to request this resource?"* It just acts.

---

### A. The Vulnerable Portal — `/`

Go to `/` and type a legitimate filename first:
```
readme.txt
```

The server reads `docs/readme.txt` and returns it. Normal.

Now try crossing outside the allowed directory:
```
../secrets/config.env
```

The server reads `secrets/config.env` — a file the web client has no business accessing. You didn't read it. The **deputy did**, on your behalf, using its own privilege. You just told it where to point.

---

### B. The Safe Portal — `/safe`

Go to `/safe` and try the same payload:
```
../secrets/config.env
```

The server resolves the real absolute path before doing anything, then checks it sits inside `docs/`. It doesn't — so access is denied before the deputy's authority is ever used outside its sanctioned scope.

---

## 5. Why This Is a Confused Deputy

The deputy (the server) is confused about who it's actually serving:

- It has authority to read files.
- The caller (you, the browser) does not.
- The server uses its authority to do whatever the caller asks — without checking if the caller should be allowed to ask for that.

The privilege isn't stolen. It's *lent out by accident*.

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
