#!/usr/bin/env python3
"""
Vulnerable Flask application using Jinja2 template engine for SSTI testing.

This application contains intentionally vulnerable endpoints to test SSTI detection.
DO NOT use this code in production environments.
"""

from flask import Flask, request, render_template_string, render_template, redirect, url_for, jsonify
import os
import sys

app = Flask(__name__)
app.secret_key = 'test_secret_key_do_not_use_in_production'

# Vulnerable templates stored as strings
VULNERABLE_TEMPLATES = {
    'search_results': '''
    <html>
    <head><title>Search Results</title></head>
    <body>
        <h1>Search Results</h1>
        <p>You searched for: {{ query }}</p>
        <div class="results">
            <!-- Results would go here -->
        </div>
    </body>
    </html>
    ''',
    
    'user_profile': '''
    <html>
    <head><title>User Profile</title></head>
    <body>
        <h1>User Profile</h1>
        <div class="bio">
            <h2>Biography</h2>
            <p>{{ bio }}</p>
        </div>
        <div class="status">
            <h2>Status</h2>
            <p>{{ status }}</p>
        </div>
    </body>
    </html>
    ''',
    
    'error_page': '''
    <html>
    <head><title>Error</title></head>
    <body>
        <h1>Error</h1>
        <p>An error occurred: {{ error_message }}</p>
        <p>Debug info: {{ debug_info }}</p>
    </body>
    </html>
    '''
}

@app.route('/')
def index():
    """Main index page with links to vulnerable endpoints."""
    return '''
    <html>
    <head><title>Jinja2 SSTI Test App</title></head>
    <body>
        <h1>Jinja2 SSTI Test Application</h1>
        <h2>Vulnerable Endpoints:</h2>
        <ul>
            <li><a href="/search?q=test">Search (GET)</a></li>
            <li><a href="/profile">Profile Form</a></li>
            <li><a href="/render?template=hello&name=world">Direct Render</a></li>
            <li><a href="/debug?msg=test">Debug Page</a></li>
            <li><a href="/api/search?q=test">API Search</a></li>
        </ul>
        
        <h2>Test Payloads:</h2>
        <ul>
            <li><code>{{7*7}}</code> - Basic math</li>
            <li><code>{{config}}</code> - Config access</li>
            <li><code>{{request}}</code> - Request object</li>
            <li><code>{{''.__class__.__mro__[2].__subclasses__()}}</code> - Class exploration</li>
        </ul>
    </body>
    </html>
    '''

@app.route('/search')
def search():
    """Vulnerable search endpoint - reflects query parameter directly."""
    query = request.args.get('q', 'default')
    # VULNERABLE: Direct template rendering with user input
    return render_template_string(VULNERABLE_TEMPLATES['search_results'], query=query)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    """Profile page with vulnerable form processing."""
    if request.method == 'GET':
        return '''
        <html>
        <body>
            <h1>Update Profile</h1>
            <form method="post">
                <label>Bio:</label><br>
                <textarea name="bio" rows="4" cols="50">Enter your bio here...</textarea><br><br>
                <label>Status:</label><br>
                <input type="text" name="status" value="Available"><br><br>
                <input type="submit" value="Update Profile">
            </form>
        </body>
        </html>
        '''
    else:
        bio = request.form.get('bio', 'No bio provided')
        status = request.form.get('status', 'Unknown')
        # VULNERABLE: Template rendering with form data
        return render_template_string(VULNERABLE_TEMPLATES['user_profile'], bio=bio, status=status)

@app.route('/render')
def direct_render():
    """Direct template rendering endpoint."""
    template_name = request.args.get('template', 'hello')
    name = request.args.get('name', 'world')
    
    # VULNERABLE: Building template string from user input
    template_str = f"<h1>Hello {name}!</h1><p>Template: {{{{ template_name }}}}</p>"
    return render_template_string(template_str, template_name=template_name)

@app.route('/debug')
def debug_page():
    """Debug page that shows error messages."""
    msg = request.args.get('msg', 'No message')
    debug_info = request.args.get('debug', 'No debug info')
    
    # VULNERABLE: Error page with user input
    return render_template_string(
        VULNERABLE_TEMPLATES['error_page'], 
        error_message=msg, 
        debug_info=debug_info
    )

@app.route('/api/search')
def api_search():
    """API endpoint that returns JSON with template rendering."""
    query = request.args.get('q', '')
    
    # VULNERABLE: Template in JSON response
    result_template = f"Search completed for: {query}"
    rendered_result = render_template_string("{{ result }}", result=result_template)
    
    return jsonify({
        'query': query,
        'result': rendered_result,
        'status': 'success'
    })

@app.route('/redirect')
def redirect_test():
    """Redirect endpoint that passes data through URL."""
    data = request.args.get('data', 'test')
    return redirect(url_for('redirect_target', info=data))

@app.route('/redirect/target')
def redirect_target():
    """Target of redirect that renders the passed data."""
    info = request.args.get('info', 'no info')
    # VULNERABLE: Rendering redirected data
    return render_template_string("<h1>Redirected</h1><p>Info: {{ info }}</p>", info=info)

@app.route('/header')
def header_test():
    """Test endpoint that uses HTTP headers."""
    user_agent = request.headers.get('User-Agent', 'Unknown')
    custom_header = request.headers.get('X-Custom', 'None')
    
    # VULNERABLE: Rendering header values
    template = '''
    <h1>Header Test</h1>
    <p>User-Agent: {{ user_agent }}</p>
    <p>Custom Header: {{ custom_header }}</p>
    '''
    return render_template_string(template, user_agent=user_agent, custom_header=custom_header)

@app.route('/cookie')
def cookie_test():
    """Test endpoint that uses cookies."""
    session_id = request.cookies.get('session_id', 'no-session')
    preferences = request.cookies.get('prefs', 'default')
    
    # VULNERABLE: Rendering cookie values
    template = '''
    <h1>Cookie Test</h1>
    <p>Session: {{ session_id }}</p>
    <p>Preferences: {{ preferences }}</p>
    '''
    return render_template_string(template, session_id=session_id, preferences=preferences)

@app.route('/advanced')
def advanced_ssti():
    """Advanced SSTI test with complex scenarios."""
    action = request.args.get('action', 'info')
    param = request.args.get('param', 'test')
    
    if action == 'config':
        # VULNERABLE: Direct config access
        return render_template_string("Config: {{ config }}")
    elif action == 'request':
        # VULNERABLE: Request object access
        return render_template_string("Request: {{ request }}")
    elif action == 'globals':
        # VULNERABLE: Global access
        return render_template_string("Globals: {{ request.application.__globals__ }}")
    elif action == 'custom':
        # VULNERABLE: Custom parameter rendering
        return render_template_string(f"Custom: {{{{ {param} }}}}")
    else:
        return render_template_string("Action: {{ action }}, Param: {{ param }}", action=action, param=param)

# Error handlers that might be vulnerable
@app.errorhandler(404)
def not_found(error):
    """404 error handler."""
    path = request.path
    # VULNERABLE: Including request path in error message
    return render_template_string(
        "<h1>404 Not Found</h1><p>The page {{ path }} was not found.</p>", 
        path=path
    ), 404

@app.errorhandler(500)
def internal_error(error):
    """500 error handler."""
    # VULNERABLE: Including error details
    return render_template_string(
        "<h1>500 Internal Error</h1><p>Error: {{ error }}</p>", 
        error=str(error)
    ), 500

if __name__ == '__main__':
    print("Starting Jinja2 SSTI Test Application")
    print("WARNING: This application contains intentional vulnerabilities!")
    print("Available endpoints:")
    print("  http://localhost:5000/ - Main page")
    print("  http://localhost:5000/search?q={{7*7}} - Search test")
    print("  http://localhost:5000/profile - Profile form")
    print("  http://localhost:5000/render?name={{config}} - Direct render")
    print("  http://localhost:5000/debug?msg={{request}} - Debug page")
    print("  http://localhost:5000/api/search?q={{7*7}} - API endpoint")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
