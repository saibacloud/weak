## CWE-432: Dangerous Signal Handler not Disabled During Sensitive Operations

A `SIGUSR1` handler and a withdraw operation both perform a non-atomic
read-modify-write on the same shared account state. Each step of the
withdraw and the signal is its own HTTP request, so you drive the race
yourself with the DevTools Network tab open and watch the payloads in
order. Vulnerable mode leaves the signal mask open; safe mode wraps the
withdraw in `pthread_sigmask(SIG_BLOCK, [SIGUSR1])` and unblocks at commit.

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
| `main.py` | FastAPI app, SIGUSR1 handler, begin/commit endpoints |

### Routes
| Route | Method | Purpose |
|-------|--------|---------|
| `/` | GET | Walkthrough page - one button per endpoint, one request per click |
| `/status` | GET | Current balance, pending withdraw, signal mask, transaction log |
| `/reset` | POST | Reset to balance=100, drop pending, unblock SIGUSR1 |
| `/withdraw/begin?amount=20&mode=vulnerable\|safe` | POST | Snapshot balance into pending; if safe, block SIGUSR1 |
| `/signal/send` | POST | `pthread_kill(MAIN_TID, SIGUSR1)` |
| `/withdraw/commit` | POST | Write `snapshot - amount`; if safe, unblock SIGUSR1 |

Nothing is orchestrated by the server. Each endpoint does one thing and
returns its observable state. The race is constructed by the order in which
you call them.

---

## 4. Demonstration

Open DevTools - Network tab - before you start. Each `Send request` button
fires exactly one fetch. Click each Network row to inspect headers / payload
/ response.

### A. Vulnerable - drive these in order

| # | Method | Endpoint | What to look for in the response |
|---|--------|----------|----------------------------------|
| V1 | POST | `/reset` | `balance: 100`, `pending: null`, `signal_blocked: false` |
| V2 | GET  | `/status` | confirms the same |
| V3 | POST | `/withdraw/begin?amount=20&mode=vulnerable` | `snapshot: 100`, `mode: vulnerable`, `signal_blocked: false` |
| V4 | POST | `/signal/send` | `signal_blocked_at_call: false`, `balance_before: 100`, `balance_after: 105` (handler already ran) |
| V5 | GET  | `/status` | `balance: 105`, transactions show INTEREST entry |
| V6 | POST | `/withdraw/commit` | `used_snapshot: 100`, `balance_before_write: 105`, `balance_after_write: 80` - the clobber |
| V7 | GET  | `/status` | `balance: 80`, final log: BEGIN, INTEREST, COMMIT |

Expected reasoning: balance should be `100 - 20 + 5 = 85`. It is `80`. The
handler's `+5` was lost because the commit used a snapshot it had taken
before the handler ran.

### B. Safe - drive these in order

| # | Method | Endpoint | What to look for in the response |
|---|--------|----------|----------------------------------|
| S1 | POST | `/reset` | mask back to open |
| S2 | POST | `/withdraw/begin?amount=20&mode=safe` | `mode: safe`, `signal_blocked: true` |
| S3 | POST | `/signal/send` | `signal_blocked_at_call: true`, `balance_before: 100`, `balance_after: 100` (queued, not delivered) |
| S4 | GET  | `/status` | `balance: 100`, no INTEREST entry yet |
| S5 | POST | `/withdraw/commit` | `balance_after_write: 80`, then `handler_ran_after_unblock: true`, `final_balance: 85` |
| S6 | GET  | `/status` | `balance: 85`, log shows BEGIN, COMMIT, then INTEREST |

The handler ran exactly once - after commit's write, on top of the new
balance. Same signal, same handler, different ordering, different result.

### curl equivalents

```bash
# Vulnerable
curl -s -X POST 'http://127.0.0.1:5000/reset'
curl -s -X POST 'http://127.0.0.1:5000/withdraw/begin?amount=20&mode=vulnerable'
curl -s -X POST 'http://127.0.0.1:5000/signal/send'
curl -s -X POST 'http://127.0.0.1:5000/withdraw/commit'
curl -s 'http://127.0.0.1:5000/status'

# Safe
curl -s -X POST 'http://127.0.0.1:5000/reset'
curl -s -X POST 'http://127.0.0.1:5000/withdraw/begin?amount=20&mode=safe'
curl -s -X POST 'http://127.0.0.1:5000/signal/send'
curl -s -X POST 'http://127.0.0.1:5000/withdraw/commit'
curl -s 'http://127.0.0.1:5000/status'
```

---

## 5. The Vulnerability in Code

**Vulnerable - begin leaves the mask open:**
```python
@app.post("/withdraw/begin")
async def withdraw_begin(amount, mode):
    state["pending"] = {"snapshot": state["balance"], "amount": amount, "mode": mode}
    # ... no signal mask is touched ...

@app.post("/withdraw/commit")
async def withdraw_commit():
    snapshot, amount = state["pending"]["snapshot"], state["pending"]["amount"]
    state["balance"] = snapshot - amount    # stale snapshot wins
```

**Safe - begin blocks, commit unblocks:**
```python
@app.post("/withdraw/begin")
async def withdraw_begin(amount, mode):
    state["pending"] = {"snapshot": state["balance"], "amount": amount, "mode": mode}
    if mode == "safe":
        signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGUSR1])

@app.post("/withdraw/commit")
async def withdraw_commit():
    snapshot, amount = state["pending"]["snapshot"], state["pending"]["amount"]
    state["balance"] = snapshot - amount
    if state["pending"]["mode"] == "safe":
        signal.pthread_sigmask(signal.SIG_UNBLOCK, [signal.SIGUSR1])  # queued signal fires here
```

---

## 6. Why It Matters

- A SIGCHLD or SIGALRM handler that touches the same data structures as a
  long-running database commit, file write, or auth state update can corrupt
  that data when the signal arrives at the wrong instruction boundary. The
  bug reproduces under load, not in tests.
- Reentrant handlers compound the problem: a handler that calls
  non-async-signal-safe functions (`malloc`, `printf`, logging libraries) can
  deadlock the process if interrupted mid-call. POSIX defines a short list
  of functions that are safe inside a handler; everything else needs to be
  masked or moved out of the handler entirely.
- Real-world fixes: `sigprocmask` / `pthread_sigmask` around the critical
  section; the self-pipe trick or `signalfd(2)` to convert signals into
  file-descriptor events the main loop drains synchronously; in Python,
  `signal.set_wakeup_fd` for the same pattern.
- Defence in depth: keep signal handlers minimal - set a flag, write to a
  pipe, increment an atomic counter - and do real work back in the main
  control flow where ordering is explicit.
