"""
CWE-432 - Dangerous Signal Handler not Disabled During Sensitive Operations

Each step of the demo is its own HTTP request. The page provides one button
per endpoint; each click fires exactly one fetch. The point is to open the
DevTools Network tab, drive the chain yourself, and watch the payloads.

Endpoints (call them in this order):
  POST /reset                                       -> clear state, unblock SIGUSR1
  POST /withdraw/begin?amount=20&mode=vulnerable    -> snapshot balance into pending
  POST /withdraw/begin?amount=20&mode=safe          -> snapshot AND block SIGUSR1
  POST /signal/send                                 -> pthread_kill(main, SIGUSR1)
  POST /withdraw/commit                             -> write snapshot-amount; if safe, unblock
  GET  /status                                      -> current balance, pending, log

Vulnerable walkthrough: handler runs the moment /signal/send is called; when
you commit, the stale snapshot clobbers the handler's interest credit.

Safe walkthrough: /withdraw/begin?mode=safe sets pthread_sigmask SIG_BLOCK.
/signal/send still fires the kernel signal but it stays pending. /withdraw/commit
writes its result first, then unblocks - the kernel delivers the pending signal
and the handler credits interest on top of the freshly written balance.
"""

import datetime
import signal
import threading
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

# Captured at module import. Uvicorn imports us on the main thread, which is
# also where the asyncio loop runs and where Python invokes signal handlers.
MAIN_TID = threading.get_ident()

INTEREST = 5

state: dict[str, Any] = {
    "balance": 100,
    "transactions": [],
    # Pending withdraw lives across HTTP requests so you can fire signals
    # between begin and commit and see what happens.
    "pending": None,  # {snapshot, amount, mode, started_at}
    "signal_blocked": False,  # mirrors the thread's sigmask for SIGUSR1
}


def _stamp(tag: str, msg: str) -> str:
    now = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    return f"[{now}] {tag:<10} {msg}"


def _block_sigusr1() -> None:
    signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGUSR1])
    state["signal_blocked"] = True


def _unblock_sigusr1() -> None:
    signal.pthread_sigmask(signal.SIG_UNBLOCK, [signal.SIGUSR1])
    state["signal_blocked"] = False


# -- Signal handler ----------------------------------------------------------
# Runs on the main thread between Python bytecodes. Same read-modify-write
# pattern as the withdraw. The two RMWs touching shared state is the weakness.


def interest_handler(signum, frame):
    snapshot = state["balance"]
    state["balance"] = snapshot + INTEREST
    state["transactions"].append(
        _stamp(
            "INTEREST",
            f"handler fired: read={snapshot} +{INTEREST} -> wrote={snapshot + INTEREST}",
        )
    )


signal.signal(signal.SIGUSR1, interest_handler)


app = FastAPI()


# -- CSS ---------------------------------------------------------------------

CSS = """
* { box-sizing: border-box; }
body { font-family: sans-serif; padding: 20px; background: #fff; color: #111; max-width: 1100px; margin: auto; }
h1, h2 { margin-bottom: 6px; }
h2 { margin-top: 26px; border-bottom: 1px solid #ccc; padding-bottom: 4px; }
p  { margin: 4px 0; }
a  { color: #111; }
.box { border: 1px solid #bbb; padding: 12px; margin: 10px 0; background: #eee; }
.bad   { border-left: 4px solid #111; }
.good  { border-left: 4px solid #888; }
.step { border: 1px solid #ccc; padding: 12px 14px; margin: 8px 0; background: #fafafa; }
.step h3 { margin: 0 0 6px 0; font-size: 1em; }
.step .meth { font-family: monospace; background: #222; color: #f0f0f0; padding: 2px 6px;
              border-radius: 2px; margin-right: 6px; font-size: 0.85em; }
.step code.url { font-family: monospace; font-size: 0.95em; }
.step button { margin-top: 8px; }
table  { border-collapse: collapse; width: 100%; margin-top: 8px; }
td, th { padding: 4px 10px; text-align: left; border-bottom: 1px solid #ccc; font-size: 0.9em; }
th     { background: #ddd; }
pre    { margin: 0; white-space: pre-wrap; word-break: break-all; font-size: 0.85em; }
code   { background: #ddd; padding: 1px 4px; border-radius: 2px; font-size: 0.85em; }
.tag-vuln { font-weight: bold; }
.tag-safe { color: #444; font-weight: bold; }
.dim   { color: #666; font-size: 0.85em; }
button { font-family: sans-serif; font-size: 0.9em; padding: 6px 12px; cursor: pointer;
         border: 1px solid #999; background: #ddd; border-radius: 2px; }
button:hover { background: #ccc; }
.result-panel { background: #f5f5f5; border: 1px solid #bbb; padding: 10px;
                margin-top: 6px; min-height: 1.2em; max-height: 320px; overflow: auto; }
.result-panel pre { font-size: 0.82em; }
.curl { background: #1e1e1e; color: #ddd; padding: 6px 10px; border-radius: 3px;
        font-family: monospace; font-size: 0.82em; margin-top: 6px; overflow-x: auto; }
.flag { display: inline-block; padding: 2px 8px; border-radius: 2px; font-size: 0.85em; }
.flag-blocked { background: #444; color: #fff; }
.flag-open    { background: #ddd; color: #222; }
"""


# -- JS: ONE button = ONE fetch. No chaining, no orchestration. -------------

SCRIPT = """
async function send(method, url, panelId) {
    const panel = document.getElementById(panelId);
    panel.innerHTML = '<pre>...</pre>';
    try {
        const resp = await fetch(url, { method });
        const text = await resp.text();
        let body = text;
        try { body = JSON.stringify(JSON.parse(text), null, 2); } catch (e) {}
        panel.innerHTML = '<pre>HTTP ' + resp.status + ' ' + resp.statusText + '\\n\\n' + body + '</pre>';
    } catch (e) {
        panel.innerHTML = '<pre>fetch error: ' + e.message + '</pre>';
    }
}
"""


def step_html(idx: str, title: str, method: str, url: str, panel_id: str) -> str:
    curl = (
        f"curl -s -X {method} 'http://127.0.0.1:5000{url}'"
        if method != "GET"
        else f"curl -s 'http://127.0.0.1:5000{url}'"
    )
    return f"""
    <div class="step">
      <h3>Step {idx}: {title}</h3>
      <div><span class="meth">{method}</span><code class="url">{url}</code></div>
      <div class="curl">{curl}</div>
      <button onclick="send('{method}', '{url}', '{panel_id}')">Send request</button>
      <div class="result-panel" id="{panel_id}"></div>
    </div>
    """


# -- Routes -----------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
async def index():
    flag_class = "flag-blocked" if state["signal_blocked"] else "flag-open"
    flag_text = "SIGUSR1: BLOCKED" if state["signal_blocked"] else "SIGUSR1: open"
    pending = state["pending"]
    pending_summary = (
        f"snapshot={pending['snapshot']}, amount={pending['amount']}, mode={pending['mode']}"
        if pending
        else "none"
    )

    log_rows = (
        "".join(
            f"<tr><td><pre>{line}</pre></td></tr>" for line in state["transactions"]
        )
        or "<tr><td><em>No activity yet.</em></td></tr>"
    )

    vuln_steps = (
        step_html("V1", "Reset state", "POST", "/reset", "p-v1")
        + step_html(
            "V2",
            "Read state (balance should be 100, no pending)",
            "GET",
            "/status",
            "p-v2",
        )
        + step_html(
            "V3",
            "Begin VULNERABLE withdraw - server snapshots balance=100, mask stays open",
            "POST",
            "/withdraw/begin?amount=20&mode=vulnerable",
            "p-v3",
        )
        + step_html(
            "V4",
            "Fire SIGUSR1 - handler runs IMMEDIATELY (mask is open) and credits +5",
            "POST",
            "/signal/send",
            "p-v4",
        )
        + step_html(
            "V5",
            "Read state - balance should now be 105 (handler ran)",
            "GET",
            "/status",
            "p-v5",
        )
        + step_html(
            "V6",
            "Commit withdraw - server writes (snapshot - amount) = 80, CLOBBERS the 105",
            "POST",
            "/withdraw/commit",
            "p-v6",
        )
        + step_html(
            "V7",
            "Read state - balance is 80, lost the +5 interest",
            "GET",
            "/status",
            "p-v7",
        )
    )

    safe_steps = (
        step_html("S1", "Reset state", "POST", "/reset", "p-s1")
        + step_html(
            "S2",
            "Begin SAFE withdraw - server snapshots AND blocks SIGUSR1",
            "POST",
            "/withdraw/begin?amount=20&mode=safe",
            "p-s2",
        )
        + step_html(
            "S3",
            "Fire SIGUSR1 - signal is queued by kernel, handler does NOT run",
            "POST",
            "/signal/send",
            "p-s3",
        )
        + step_html(
            "S4",
            "Read state - balance still 100, no INTEREST log entry yet",
            "GET",
            "/status",
            "p-s4",
        )
        + step_html(
            "S5",
            "Commit withdraw - server writes 80, then unblocks; pending signal fires, handler reads 80 -> 85",
            "POST",
            "/withdraw/commit",
            "p-s5",
        )
        + step_html(
            "S6",
            "Read state - balance is 85, interest preserved",
            "GET",
            "/status",
            "p-s6",
        )
    )

    return f"""
    <html>
    <head><title>CWE-432</title><style>{CSS}</style></head>
    <body>

    <h1>CWE-432 - Dangerous Signal Handler not Disabled During Sensitive Operations</h1>
    <p>
      Server-side state: balance = <strong>{state["balance"]}</strong>
      &middot; pending = <code>{pending_summary}</code>
      &middot; <span class="flag {flag_class}">{flag_text}</span>
      &middot; <a href="/">refresh</a>
    </p>

    <p>
      A <code>SIGUSR1</code> handler does <code>balance = read + {INTEREST}</code>.
      A withdraw operation does its own <code>read -&gt; (other requests) -&gt; write</code>,
      but split across separate HTTP requests so you can fire the signal between
      them yourself.
    </p>

    <div class="box bad">
      <p class="tag-vuln">&#9888; VULNERABLE - begin leaves SIGUSR1 unmasked</p>
      <p>The signal fires the instant you call <code>/signal/send</code>. When you
         later <code>/withdraw/commit</code>, the server still holds the snapshot
         from before the handler ran and writes <code>snapshot - amount</code>
         straight over the top of the handler's update.</p>
    </div>

    <div class="box good">
      <p class="tag-safe">&#10003; SAFE - begin masks SIGUSR1 for the critical section</p>
      <p><code>pthread_sigmask(SIG_BLOCK, [SIGUSR1])</code> is set in
         <code>/withdraw/begin?mode=safe</code> and stays set on the main thread
         until <code>/withdraw/commit</code> unblocks it. SIGUSR1 sent in between
         is held pending by the kernel and only delivered after the commit's write.</p>
    </div>

    <h2>Vulnerable walkthrough</h2>
    {vuln_steps}

    <h2>Safe walkthrough</h2>
    {safe_steps}


    <script>{SCRIPT}</script>
    </body>
    </html>
    """


@app.post("/reset", response_class=JSONResponse)
async def reset():
    # Always unblock so a half-finished safe-mode flow doesn't leave the mask set.
    if state["signal_blocked"]:
        _unblock_sigusr1()
    state["balance"] = 100
    state["transactions"] = []
    state["pending"] = None
    state["transactions"].append(
        _stamp("RESET", "balance=100, pending=None, SIGUSR1 unblocked")
    )
    return JSONResponse(
        {
            "action": "reset",
            "balance": state["balance"],
            "pending": state["pending"],
            "signal_blocked": state["signal_blocked"],
            "explanation": "State cleared. Signal mask returned to its default (unblocked).",
        }
    )


@app.post("/withdraw/begin", response_class=JSONResponse)
async def withdraw_begin(amount: int = 20, mode: str = "vulnerable"):
    if mode not in ("vulnerable", "safe"):
        raise HTTPException(400, "mode must be 'vulnerable' or 'safe'")
    if state["pending"] is not None:
        raise HTTPException(
            409,
            f"already a pending withdraw ({state['pending']}); commit or reset first",
        )

    snapshot = state["balance"]
    state["pending"] = {
        "snapshot": snapshot,
        "amount": amount,
        "mode": mode,
        "started_at": datetime.datetime.now().isoformat(timespec="milliseconds"),
    }
    state["transactions"].append(
        _stamp("BEGIN", f"mode={mode}: snapshotted balance={snapshot}, amount={amount}")
    )
    if mode == "safe":
        _block_sigusr1()
        state["transactions"].append(
            _stamp("BEGIN", "SIGUSR1 BLOCKED via pthread_sigmask")
        )

    return JSONResponse(
        {
            "action": "withdraw_begin",
            "mode": mode,
            "snapshot": snapshot,
            "amount": amount,
            "balance_now": state["balance"],
            "signal_blocked": state["signal_blocked"],
            "explanation": (
                "Snapshot captured into server-side 'pending' state. "
                + (
                    "Signal mask UNCHANGED - SIGUSR1 will be delivered the moment it is sent."
                    if mode == "vulnerable"
                    else "Signal mask now BLOCKS SIGUSR1 on the main thread until commit unblocks it."
                )
            ),
            "next": "POST /signal/send  then  POST /withdraw/commit",
        }
    )


@app.post("/signal/send", response_class=JSONResponse)
async def signal_send():
    blocked_at_call = state["signal_blocked"]
    balance_before = state["balance"]
    # Target the main thread directly so we know exactly where the signal lands.
    # If the main thread has SIGUSR1 unblocked, the handler fires before pthread_kill
    # returns (POSIX self-signal semantics) and balance is already changed by the
    # time we serialise the response. If blocked, the kernel queues it.
    signal.pthread_kill(MAIN_TID, signal.SIGUSR1)
    state["transactions"].append(
        _stamp(
            "SIGNAL",
            "pthread_kill(MAIN, SIGUSR1) sent"
            + (
                " (queued - mask is blocked)"
                if blocked_at_call
                else " (delivered immediately)"
            ),
        )
    )
    return JSONResponse(
        {
            "action": "signal_send",
            "signal": "SIGUSR1",
            "delivered_to_thread_id": MAIN_TID,
            "signal_blocked_at_call": blocked_at_call,
            "balance_before": balance_before,
            "balance_after": state["balance"],
            "explanation": (
                "Kernel queued the signal because SIGUSR1 is masked on the main "
                "thread. Handler will run when /withdraw/commit unblocks the mask."
                if blocked_at_call
                else "Handler ran on the main thread before pthread_kill returned. "
                f"It read balance={balance_before}, wrote balance={state['balance']}."
            ),
        }
    )


@app.post("/withdraw/commit", response_class=JSONResponse)
async def withdraw_commit():
    pending = state["pending"]
    if pending is None:
        raise HTTPException(400, "no pending withdraw - call /withdraw/begin first")

    snapshot = pending["snapshot"]
    amount = pending["amount"]
    mode = pending["mode"]
    balance_before_write = state["balance"]

    new_balance = snapshot - amount
    state["balance"] = new_balance
    state["transactions"].append(
        _stamp(
            "COMMIT",
            f"mode={mode}: wrote balance = snapshot({snapshot}) - amount({amount}) = {new_balance}",
        )
    )
    state["pending"] = None

    handler_ran_after = False
    if mode == "safe":
        # Unblocking delivers any pending SIGUSR1 right now; Python runs the
        # registered handler at the next bytecode boundary on this thread.
        balance_before_unblock = state["balance"]
        _unblock_sigusr1()
        state["transactions"].append(_stamp("COMMIT", "SIGUSR1 UNBLOCKED"))
        # Touching a bytecode or two is enough for the handler to fire. We don't
        # need asyncio.sleep here because we're synchronous now - any pending
        # signal has already been delivered between unblock and this line.
        handler_ran_after = state["balance"] != balance_before_unblock

    return JSONResponse(
        {
            "action": "withdraw_commit",
            "mode": mode,
            "used_snapshot": snapshot,
            "amount": amount,
            "balance_before_write": balance_before_write,
            "balance_after_write": new_balance,
            "final_balance": state["balance"],
            "handler_ran_after_unblock": handler_ran_after,
            "signal_blocked": state["signal_blocked"],
            "explanation": (
                f"Wrote snapshot({snapshot}) - amount({amount}) = {new_balance}. "
                + (
                    "Vulnerable mode: if SIGUSR1 fired between begin and commit, the "
                    "handler's write was overwritten by this commit. Compare "
                    "balance_before_write to balance_after_write to see the clobber."
                    if mode == "vulnerable"
                    else "Safe mode: unblock fired the queued handler on top of the "
                    "freshly-written balance. Compare balance_after_write to final_balance."
                )
            ),
        }
    )


@app.get("/status", response_class=JSONResponse)
async def status():
    return JSONResponse(
        {
            "balance": state["balance"],
            "pending": state["pending"],
            "signal_blocked": state["signal_blocked"],
            "transactions": state["transactions"],
        }
    )
