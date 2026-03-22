## Type A (Reflective) & B (Stored) XSS Vulnerability Demonstration

This app demonstrates **Cross-Site Scripting (XSS)** vulnerabilities in two ways:
1. **Vulnerable endpoints** - Shows how XSS attacks work
2. **Safe mode endpoints** - Shows proper protection with HTML escaping

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

### Database Lists
- **Vulnerable `my_guestbook`**: Stores comments without sanitization
- **Safe `safe_guestbook`**: Stores comments the same way, but displayed with HTML escaping

### Routes
| Route | Method | Purpose |
|-------|--------|---------|
| `/` | GET | Display vulnerable guestbook |
| `/` | POST | Add comment to vulnerable guestbook |
| `/search` | GET | Demonstrate reflected XSS |
| `/safe` | GET | Display safe guestbook with escaped HTML |
| `/safe` | POST | Add comment to safe guestbook |

---

## 4. Demonstration

### A. Reflected XSS
Go to `/search` and try:

**Example:**
```
<script>alert('XSS in your app');</script>
```

**Or something a bit more meaningful:**
```
<script>alert('Your cookie: ' + document.cookie);</script>
```

### B. Stored XSS (payload exists on the server)
Go to `/` and type:

**Simple Alert:**
```
<script>alert('Stored XSS go brrr');</script>
```

**Persistent Payload:**
```html
<img src=x onerror="this.textContent='Get pwned! Even if you refresh the page, it persists'">
```

**Style Injection:**
```html
<div style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: red; z-index: 9999;"></div>
```

As the payload stays in the database, every visitor is hit by it.

---

## 5. Safety with Escaping

Go to `/safe` to see the same functionality but **secure**:

1. **XSS payloads** - they won't execute
2. **The data is stored** normally in `safe_guestbook`
3. **Displayed with escaping** using Python `html.escape()`

---

## 6. Some notes

**Reflected XSS (in `/search`):**

***This example is a QoL feature, it just shows the user what they typed as a response to their input and injects into HTML directly, nothing is stored on the server.***
```python

content_area = f"<div class='box'><h3>You searched for: {q}</h3>"
```
The variable `{q}` is never escaped, so `<script>` becomes actual JavaScript.

**Stored XSS (in `/`):**

***This is submitting unsanitized data directly into a database. The payload is staged in a database, waiting to be unknowingly called by an unsuspecting user. When the payload is called, the user will get that payload executed.***

```python


comments_html += f"<div class='box'>{c}</div>"
```
Any comment stored in `my_guestbook` is rendered as-is.


***This can lead to a number of outcomes, but most commonly this is used to steal cookies and session tokens, but can exfil other sensitive information.*** 
