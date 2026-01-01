from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/')
def home():
    return "<h1>Welcome to the Mock Target</h1><p>This site is intentionally vulnerable.</p><!-- HTML Comment: Dev note - check /admin -->"

@app.route('/admin')
def admin():
    return "<h1>Admin Panel</h1><p>Enter credentials...</p>"

@app.route('/config.json')
def config():
    # Exposed configuration file (Information Disclosure)
    return jsonify({
        "debug": True,
        "database_host": "db.prod.internal",
        "api_key": "AIzaSyD-EXAMPLE-API-KEY-12345",
        "secret": "s3cr3t_p@ssw0rd"
    })

@app.route('/search')
def search():
    # Reflected XSS Vulnerability
    query = request.args.get('q', '')
    # VULNERABLE: Direct reflection of input
    return f"<h1>Search Results for: {query}</h1><p>No results found.</p>"

@app.route('/robots.txt')
def robots():
    return "User-agent: *\nDisallow: /secret-folder/"

@app.route('/secret-folder/')
def secret():
    return "<h1>You found the secret folder!</h1>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
