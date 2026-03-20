from fastapi import FastAPI, Request, Query
from fastapi.responses import HTMLResponse
from html import escape

# Initialize FastAPI App
app = FastAPI()


# List to store guestbook comments (this is our database).
my_guestbook = [
    "Welcome to my site!"
]

# Safe version for demonstrating proper database updates
safe_guestbook = [
    "Welcome to my site (Safe Mode)!"
]

# --- Type A (Reflected XSS) ---


@app.get("/search", response_class=HTMLResponse)
async def search(q: str = Query(None)):
    # I handle the query parameter 'q'.
    # If 'q' is missing, it defaults to None.

    content_area = ""
    if q:
        # VULNERABILITY: I take 'q' and put it directly into the HTML string.
        # I do this so the user sees exactly what they typed.
        content_area = f"""
        <div class="box">
            <h3>You searched for: {q}</h3>
            <p>No results found.</p>
        </div>
        """

    html_content = f"""
    <html>
    <head>
        <title>My Search</title>
        <style>
            body {{ font-family: sans-serif; padding: 20px; }}
            .box {{ border: 1px solid #ddd; padding: 10px; margin-top: 10px; background: #eee; }}
        </style>
    </head>
    <body>
        <div style="margin-bottom:20px;">
            <a href="/">My Guestbook</a> | <a href="/search">My Search Engine</a>
        </div>

        <h1>Search My Site</h1>
        <form method="GET">
            <!-- I also inject 'q' into the input value so the box stays filled. -->
            <input type="text" name="q" value="{q if q else ""}">
            <button type="submit">Search</button>
        </form>

        {content_area}
    </body>
    </html>
    """
    return html_content


# --- Type B (Stored XSS) ---
@app.get("/", response_class=HTMLResponse)
async def display_guestbook():
    # I generate the HTML for the GET request.
    # I iterate over my_guestbook to show comments.
    # VULNERABILITY: I inject the comment string directly into the HTML.
    # I assume the data is safe because it came from my database.

    comments_html = ""
    for c in my_guestbook:
        # I intentionally do not escape 'c' here. I want the HTML to render as-is.
        comments_html += f"<div class='box'>{c}</div>"

    html_content = f"""
    <html>
    <head>
        <title>My Project</title>
        <style>
            body {{ font-family: sans-serif; padding: 20px; }}
            .box {{ border: 1px solid #ccc; padding: 10px; margin: 10px 0; background: #f9f9f9; }}
            input {{ width: 300px; padding: 5px; }}
        </style>
    </head>
    <body>
        <div style="margin-bottom:20px;">
            <a href="/">My Guestbook</a> | <a href="/search">My Search Engine</a>
        </div>

        <h1>My Guestbook</h1>
        <form method="POST">
            <input type="text" name="comment" placeholder="Type a message..." required>
            <button type="submit">Sign Guestbook</button>
        </form>
        <hr>
        
        <h2>Previous Messages:</h2>
        {comments_html}
    </body>
    </html>
    """
    return html_content


@app.post("/", response_class=HTMLResponse)
async def add_comment(request: Request):
    global my_guestbook
    try:
        # I extract the form data manually.
        form_data = await request.form()

        # I get the specific comment.
        user_comment = form_data.get('comment')

        # I save it exactly as received. I don't want to alter the user's input.
        if user_comment:
            my_guestbook.append(user_comment)

        # After saving, I call display_guestbook() to refresh and show the new comment.
        return await display_guestbook()
    except Exception as e:
        return f"""
        <html>
        <body>
            <h2>Error</h2>
            <p>Failed to add comment: {str(e)}</p>
            <a href="/">Back to Guestbook</a>
        </body>
        </html>
        """


# --- SAFE MODE: Properly escaped HTML (for comparison) ---
@app.get("/safe", response_class=HTMLResponse)
async def display_safe_guestbook():
    # This demonstrates proper database list updates with HTML escaping.
    # Comments are escaped before rendering, preventing XSS.

    comments_html = ""
    for c in safe_guestbook:
        # SECURE: I escape the comment to prevent XSS injection.
        comments_html += f"<div class='box'>{escape(c)}</div>"

    html_content = f"""
    <html>
    <head>
        <title>My Project (Safe Mode)</title>
        <style>
            body {{ font-family: sans-serif; padding: 20px; }}
            .box {{ border: 1px solid #ccc; padding: 10px; margin: 10px 0; background: #f0f8ff; }}
            input {{ width: 300px; padding: 5px; }}
            .safe-badge {{ background: #90EE90; padding: 5px 10px; border-radius: 5px; margin: 10px 0; }}
        </style>
    </head>
    <body>
        <div style="margin-bottom:20px;">
            <a href="/">My Guestbook (Vulnerable)</a> | 
            <a href="/search">My Search Engine (Vulnerable)</a> |
            <a href="/safe">Safe Guestbook (Secure)</a>
        </div>

        <h1>My Guestbook (Safe Mode)</h1>
        <div class="safe-badge">✓ This version properly escapes HTML - try XSS here, it won't work!</div>
        
        <form method="POST" action="/safe">
            <input type="text" name="comment" placeholder="Type a message..." required>
            <button type="submit">Sign Guestbook</button>
        </form>
        <hr>
        
        <h2>Previous Messages:</h2>
        {comments_html}
    </body>
    </html>
    """
    return html_content


@app.post("/safe", response_class=HTMLResponse)
async def add_safe_comment(request: Request):
    global safe_guestbook
    try:
        # I extract the form data.
        form_data = await request.form()

        # I get the comment.
        user_comment = form_data.get('comment')

        # I save it exactly as received.
        if user_comment:
            safe_guestbook.append(user_comment)

        # After saving, I refresh and show the new comment (escaped).
        return await display_safe_guestbook()
    except Exception as e:
        return f"""
        <html>
        <body>
            <h2>Error</h2>
            <p>Failed to add comment: {str(e)}</p>
            <a href="/safe">Back to Safe Guestbook</a>
        </body>
        </html>
        """
