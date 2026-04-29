## CWE-NNN: [Full Title from MITRE]

[One paragraph: what the weakness is and what this demo shows.
Match the module docstring in main.py — 3–5 sentences.]

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
| `main.py` | FastAPI app |

### Routes
| Route | Method | Purpose |
|-------|--------|---------|
| `/` | GET | Home — overview and demo instructions |
| `/demo/vulnerable` | GET | [What it does — why it is vulnerable] |
| `/demo/safe` | GET | [What it does — why it is safe] |

---

## 4. Demonstration

### A. Vulnerable — [route or action name]

1. [Step: what to open]
2. [Step: what to do]
3. [Step: what to observe — include the expected JSON or UI output]

### B. Safe — [route or action name]

1. [Step: same action against the safe endpoint]
2. [Step: what changes — expected JSON or UI output]

---

## 5. The Vulnerability in Code

**Vulnerable:**
```python
# [Minimal snippet showing the unsafe pattern]
```

**Safe:**
```python
# [Minimal snippet showing the fix]
```

---

## 6. Why It Matters

- [Real-world scenario where this weakness causes harm]
- [Real-world scenario 2]
- [Real-world mitigation beyond the demo fix]
- [Real-world mitigation 2]
