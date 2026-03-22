## Type A (Reflective) & B (Stored) XSS Vulnerability Demonstration

This app demonstrates **Cross-Site Scripting (XSS)** vulnerabilities in two ways:
1. **Vulnerable endpoints** - Shows how XSS attacks work
2. **Safe mode endpoints** - Shows proper protection with HTML escaping

---

## 1. INSTALLATION
Install the required libraries:
```bash
pip install -r requirements.txt
```

## 2. STARTING THE SERVER
Open terminal, navigate to project folder, run:
```bash
uvicorn main:app --reload --port 5000
```

## 3. ACCESSING THE SITE
Open browser to:
```
http://127.0.0.1:5000
```

---

## 4. ARCHITECTURE

### Database Lists
- **Vulnerable `my_guestbook`**: Stores comments without sanitization
- **Safe `safe_guestbook`**: Stores comments the same way, but displays them with HTML escaping

### Routes
| Route | Method | Purpose |
|-------|--------|---------|
| `/` | GET | Display vulnerable guestbook |
| `/` | POST | Add comment to vulnerable guestbook |
| `/search` | GET | Demonstrate reflected XSS |
| `/safe` | GET | Display safe guestbook with escaped HTML |
| `/safe` | POST | Add comment to safe guestbook |

---

## 5. TESTING VULNERABILITIES

### A. REFLECTED XSS (Search Page)
Go to `/search` and try:

**Simple Alert:**
```
<script>alert('XSS in FastAPI');</script>
```

**Cookie Stealer (Educational):**
```
<script>alert('Your cookie: ' + document.cookie);</script>
```

**DOM Manipulation:**
```
<img src=x onerror="alert('Image XSS!')">
```

**Or in the URL directly:**
```
http://127.0.0.1:5000/search?q=<script>alert(1)</script>
```

### B. STORED XSS (Vulnerable Guestbook)
Go to `/` and type:

**Simple Alert:**
```
<script>alert('Stored XSS!');</script>
```

**Persistent Payload:**
```html
<img src=x onerror="this.textContent='Pwned! Refresh - it persists!'">
```

**Style Injection:**
```html
<div style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: red; z-index: 9999;"></div>
```

After submitting, the payload stays in the database. Every visitor sees it. This is the danger of stored XSS.

---

## 6. DEMONSTRATING SECURE DATABASE UPDATES

Go to `/safe` to see the same functionality but **secure**:

1. **Try XSS payloads** - they won't execute
2. **The data is stored** normally in `safe_guestbook`
3. **But displayed with escaping** using Python's `html.escape()`

**Compare side-by-side:**
- Vulnerable: `/` - Try: `<b>Bold text</b>` → renders as **bold**
- Safe: `/safe` - Try: `<b>Bold text</b>` → displays as `&lt;b&gt;Bold text&lt;/b&gt;`

---

## 7. TECHNICAL DETAILS

### Why Vulnerabilities Exist

**Reflected XSS (in `/search`):**
```python
# VULNERABLE - takes user input and injects into HTML directly
content_area = f"<div class='box'><h3>You searched for: {q}</h3>"
```
The variable `{q}` is never escaped, so `<script>` becomes actual JavaScript.

**Stored XSS (in `/`):**
```python
# VULNERABLE - database content rendered without escaping
comments_html += f"<div class='box'>{c}</div>"
```
Any comment stored in `my_guestbook` is rendered as-is.

### How Safe Mode Fixes It

**Safe Version:**
```python
# SECURE - use html.escape() before rendering
comments_html += f"<div class='box'>{escape(c)}</div>"
```
Now `<script>` becomes `&lt;script&gt;` - just harmless text.

---

## 8. KEY LESSONS

| Problem | Safe Mode Fix | Why It Works |
|---------|---------------|--------------|
| Reflected XSS | Use template escaping | Browser can't execute escaped HTML |
| Stored XSS | Escape on output (not input) | Stores raw data, but displays safely |
| General | Never trust user input | Always escape before rendering |

---

## 9. ERROR HANDLING

Both vulnerable and safe endpoints now include try-catch error handling:
- **Form submission errors** are caught and displayed
- **No more 500 errors** - users see helpful messages
- **Logs stack traces** for debugging

