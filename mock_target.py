from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI()

@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Vulnerable Mock Target</title>
        <style>body { font-family: sans-serif; padding: 20px; background: #f0f0f0; }</style>
    </head>
    <body>
        <h1>Welcome to Mock Target</h1>
        <p>This site simulates a vulnerable application for recon testing.</p>
        
        <hr>
        <h3>Navigation</h3>
        <ul>
            <li><a href="/login.php?next=dashboard">Login (Open Redirect?)</a></li>
            <li><a href="/product?id=10">View Product 10 (SQLi?)</a></li>
            <li><a href="/product?id=20&category=books">View Product 20</a></li>
            <li><a href="/search?q=test-query">Search (XSS?)</a></li>
            <li><a href="/about-us">About Us</a></li>
        </ul>

        <hr>
        <h3>Hidden/Sensitive Assets</h3>
        <ul>
            <!-- Katana should find these -->
            <li><a href="/admin/config.json">Client Config (Secret)</a></li>
            <li><a href="/api/v1/users">API Users endpoint</a></li>
            <li><a href="/file_viewer.php?file=/etc/passwd">File Viewer (LFI?)</a></li>
            <li><a href="/debug/env">Env Dump</a></li>
        </ul>
        
        <script>
            console.log("App loaded");
            const apiKey = "AIzaSyD-FakeKey-12345";
            // Katana JS crawling should might find this or grep will find it in source
        </script>
    </body>
    </html>
    """

@app.get("/login.php")
def login(next: str = "/"):
    return f"Login page. Next: {next}"

@app.get("/product")
def product(id: int, category: str = "generic"):
    return {"id": id, "name": "Simulated Product", "category": category}

@app.get("/search")
def search(q: str):
    return f"Search results for: {q}"

@app.get("/admin/config.json")
def config():
    return {"db_host": "localhost", "secret": "s3cr3t_p@ssw0rd", "aws_key": "AKIAIOSFODNN7EXAMPLE"}

@app.get("/api/v1/users")
def users():
    return [{"id": 1, "username": "admin"}, {"id": 2, "username": "guest"}]

@app.get("/debug/env")
def env():
    return "AWS_ACCESS_KEY_ID=AKIA..."
