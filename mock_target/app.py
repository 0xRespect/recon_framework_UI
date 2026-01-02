from flask import Flask, request, jsonify, redirect, Response

app = Flask(__name__)

@app.route('/')
def home():
    return """
    <html>
    <head><title>Vulnerable Mock Target</title></head>
    <body>
        <h1>Welcome to the Mock Target</h1>
        <p>This site is intentionally vulnerable for testing.</p>
        <ul>
            <li><a href="/search?q=test">Reflected XSS Test</a></li>
            <li><a href="/product?id=1">SQL Injection Test</a></li>
            <li><a href="/view?page=about.html">LFI Test</a></li>
            <li><a href="/redirect?url=http://google.com">Open Redirect Test</a></li>
            <li><a href="/config.json">Sensitive Config</a></li>
            <li><a href="/admin">Admin Panel</a></li>
        </ul>
        <!-- Dev note: check /backup -->
    </body>
    </html>
    """

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

@app.route('/product')
def product():
    # SQL Vulnerability Simulation
    # Vulnerable parameter: id
    product_id = request.args.get('id', '')
    
    if "'" in product_id or '"' in product_id:
        return "ERROR: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 1", 500
    
    if product_id == '1':
        return "<h1>Product 1</h1><p>Description of product 1.</p>"
    elif product_id == '2':
        return "<h1>Product 2</h1><p>Description of product 2.</p>"
    else:
        return "<h1>Product Not Found</h1>"

@app.route('/view')
def view():
    # LFI Vulnerability Simulation
    # Vulnerable parameter: page
    page = request.args.get('page', '')
    
    if "../" in page or "..%2f" in page.lower():
        # Simulate successful LFI
        return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    
    if page == "about.html":
        return "<h1>About Us</h1><p>We are a mock company.</p>"
    else:
        return f"Error: File {page} not found."

@app.route('/redirect')
def open_redirect():
    # Open Redirect Vulnerability
    # Vulnerable parameter: url
    target_url = request.args.get('url', '')
    if target_url:
        return redirect(target_url, code=302)
    return "No URL provided."

@app.route('/robots.txt')
def robots():
    return "User-agent: *\nDisallow: /secret-folder/\nDisallow: /backup"

@app.route('/secret-folder/')
def secret():
    return "<h1>You found the secret folder!</h1>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
