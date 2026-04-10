## CWE-403: Exposure of File Descriptor to Unintended Control Sphere

This app demonstrates **CWE-403**, where a server holds a privileged file descriptor
open and spawns a subprocess **without closing it first** — silently handing the child
full read access to a resource it was never meant to touch.

> Linux note: this demo requires `/proc/self/fd/` — run on Linux or WSL.

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
| `secrets.txt` | Privileged file opened at server startup; fd kept alive |
| `worker.py`   | Subprocess — enumerates `/proc/self/fd/` and reads inherited fds |
| `main.py`     | FastAPI app |

### Routes
| Route | close_fds | Result |
|-------|-----------|--------|
| `/` | — | Home — shows server fd, secrets content, run log |
| `/process/vulnerable` | `False` | Subprocess inherits all fds; reads secrets.txt |
| `/process/safe`       | `True`  | Subprocess inherits nothing above stderr |

---

## 4. Demonstration

### Step 1 — Note the fd number
The home page shows `secrets.txt` is open as e.g. **fd 3**.

### Step 2 — Open DevTools → Network tab

### Step 3 — Hit the vulnerable endpoint
Navigate to `http://127.0.0.1:5000/process/vulnerable`

In the Network tab, inspect the JSON response. You'll see:

```json
{
  "mode": "VULNERABLE",
  "close_fds": false,
  "server_secret_fd": 3,
  "inherited_fds": [
    {
      "fd": 3,
      "resolved": "/path/to/secrets.txt",
      "readable": true,
      "is_secret_fd": true,
      "content": "DB_HOST=internal-db.prod.local\nDB_PASS=sUp3rS3cr3t!..."
    }
  ]
}
```

The subprocess read the full secrets file **without knowing its path** —
purely by inheriting the fd and reading through `/proc/self/fd/3`.

### Step 4 — Hit the safe endpoint
Navigate to `http://127.0.0.1:5000/process/safe`

```json
{
  "mode": "SAFE",
  "close_fds": true,
  "inherited_fds": []
}
```

`inherited_fds` is empty. The subprocess was exec'd with all fds above stderr closed.
It has nothing to enumerate.

---

## 5. The Vulnerability in Code

**Vulnerable — fd survives into child:**
```python
# close_fds=False: child inherits everything the parent had open
subprocess.run([sys.executable, "worker.py"], close_fds=False)
```

**Safe — fd closed before exec:**
```python
# close_fds=True: all fds > 2 are closed before exec (Python 3.2+ default)
subprocess.run([sys.executable, "worker.py"], close_fds=True)
```

**Or set at open time with O_CLOEXEC:**
```python
fd = os.open("secrets.txt", os.O_RDONLY | os.O_CLOEXEC)
# fd is automatically closed on any exec(), regardless of close_fds
```

---

## 6. Why This Matters

A certificate may be revoked because:
- The server opens DB credentials, API keys, or a Unix admin socket at startup
- A user request triggers an external tool (image resize, PDF convert, ffmpeg, etc.)
- That tool enumerates `/proc/self/fd/` — a one-liner in any language
- It reads anything readable, exfiltrates it, or passes it to an attacker-controlled process

The parent developer never intended to share those resources.
They simply forgot that `fork()` + `exec()` copies the entire fd table by default.

Real-world fixes:
- **`close_fds=True`** on every `subprocess` call (Python 3.2+ default — but easy to accidentally set False)
- **`O_CLOEXEC`** at open time — belt-and-suspenders; survives even if someone passes `close_fds=False`
- **Audit all `subprocess` / `os.system` / `popen` calls** in server code
- **Principle of least privilege** — don't hold privileged fds open longer than necessary
