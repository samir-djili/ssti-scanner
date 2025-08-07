#!/usr/bin/env python3
"""
Vulnerable Django application using Django Templates for SSTI testing.

This application contains intentionally vulnerable endpoints to test SSTI detection.
DO NOT use this code in production environments.
"""

import os
import sys
import django
from django.conf import settings
from django.http import HttpResponse, JsonResponse
from django.template import Template, Context
from django.template.loader import render_to_string
from django.urls import path, include
from django.core.wsgi import get_wsgi_application
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render

# Configure Django settings
if not settings.configured:
    settings.configure(
        DEBUG=True,
        SECRET_KEY='test_secret_key_do_not_use_in_production',
        ROOT_URLCONF=__name__,
        INSTALLED_APPS=[
            'django.contrib.contenttypes',
            'django.contrib.auth',
        ],
        TEMPLATES=[{
            'BACKEND': 'django.template.backends.django.DjangoTemplates',
            'DIRS': [],
            'APP_DIRS': True,
            'OPTIONS': {
                'context_processors': [
                    'django.template.context_processors.debug',
                    'django.template.context_processors.request',
                    'django.contrib.auth.context_processors.auth',
                ],
            },
        }],
        MIDDLEWARE=[
            'django.middleware.security.SecurityMiddleware',
            'django.middleware.common.CommonMiddleware',
            'django.middleware.csrf.CsrfViewMiddleware',
            'django.contrib.auth.middleware.AuthenticationMiddleware',
        ],
        USE_TZ=True,
        ALLOWED_HOSTS=['*']
    )

django.setup()

def index(request):
    """Main index page with links to vulnerable endpoints."""
    html = '''
    <html>
    <head><title>Django Templates SSTI Test App</title></head>
    <body>
        <h1>Django Templates SSTI Test Application</h1>
        <h2>Vulnerable Endpoints:</h2>
        <ul>
            <li><a href="/search?q=test">Search (GET)</a></li>
            <li><a href="/profile">Profile Form</a></li>
            <li><a href="/render?content=hello">Direct Render</a></li>
            <li><a href="/debug?info=test">Debug Page</a></li>
            <li><a href="/api/data?query=test">API Data</a></li>
        </ul>
        
        <h2>Test Payloads:</h2>
        <ul>
            <li><code>{{7|add:"7"}}</code> - Math with add filter</li>
            <li><code>{% debug %}</code> - Debug information</li>
            <li><code>{{settings.SECRET_KEY}}</code> - Settings access</li>
            <li><code>{{request.META}}</code> - Request metadata</li>
        </ul>
    </body>
    </html>
    '''
    return HttpResponse(html)

def search(request):
    """Vulnerable search endpoint - reflects query parameter through template."""
    query = request.GET.get('q', 'default')
    
    # VULNERABLE: Direct template rendering with user input
    template_str = '''
    <html>
    <head><title>Search Results</title></head>
    <body>
        <h1>Search Results</h1>
        <p>You searched for: {{ query }}</p>
        <div class="results">
            <p>Search term processed: {{ query|upper }}</p>
            <p>Length: {{ query|length }}</p>
        </div>
    </body>
    </html>
    '''
    
    template = Template(template_str)
    context = Context({'query': query, 'request': request})
    return HttpResponse(template.render(context))

@csrf_exempt
def profile(request):
    """Profile page with vulnerable form processing."""
    if request.method == 'GET':
        form_html = '''
        <html>
        <body>
            <h1>Update Profile</h1>
            <form method="post">
                <label>Name:</label><br>
                <input type="text" name="name" value="User"><br><br>
                <label>Bio:</label><br>
                <textarea name="bio" rows="4" cols="50">Enter your bio...</textarea><br><br>
                <label>Signature:</label><br>
                <input type="text" name="signature" value="Best regards"><br><br>
                <input type="submit" value="Update Profile">
            </form>
        </body>
        </html>
        '''
        return HttpResponse(form_html)
    else:
        name = request.POST.get('name', 'Anonymous')
        bio = request.POST.get('bio', 'No bio')
        signature = request.POST.get('signature', 'No signature')
        
        # VULNERABLE: Template rendering with form data
        template_str = '''
        <html>
        <body>
            <h1>Profile Updated</h1>
            <div class="profile">
                <h2>{{ name }}</h2>
                <div class="bio">
                    <h3>Biography</h3>
                    <p>{{ bio }}</p>
                </div>
                <div class="signature">
                    <h3>Signature</h3>
                    <p>{{ signature }}</p>
                </div>
            </div>
            <p>Profile updated at: {% now "Y-m-d H:i:s" %}</p>
        </body>
        </html>
        '''
        
        template = Template(template_str)
        context = Context({
            'name': name, 
            'bio': bio, 
            'signature': signature,
            'request': request
        })
        return HttpResponse(template.render(context))

def direct_render(request):
    """Direct template rendering endpoint."""
    content = request.GET.get('content', 'hello world')
    template_type = request.GET.get('type', 'simple')
    
    # VULNERABLE: Building template from user input
    if template_type == 'debug':
        template_str = f'''
        <h1>Debug Content</h1>
        <p>Content: {content}</p>
        <div>Debug: {{% debug %}}</div>
        '''
    elif template_type == 'settings':
        template_str = f'''
        <h1>Settings Content</h1>
        <p>Content: {content}</p>
        <p>Secret: {{{{ settings.SECRET_KEY }}}}</p>
        '''
    else:
        template_str = f'''
        <h1>Simple Content</h1>
        <p>{{ content }}</p>
        <p>Processed: {{{{ content|upper }}}}</p>
        '''
    
    template = Template(template_str)
    context = Context({
        'content': content,
        'request': request,
        'settings': settings
    })
    return HttpResponse(template.render(context))

def debug_page(request):
    """Debug page that shows system information."""
    info = request.GET.get('info', 'No info')
    level = request.GET.get('level', 'basic')
    
    # VULNERABLE: Debug information with user input
    if level == 'advanced':
        template_str = '''
        <h1>Advanced Debug</h1>
        <p>Info: {{ info }}</p>
        <div>{% debug %}</div>
        <p>Request META: {{ request.META }}</p>
        <p>Settings DEBUG: {{ settings.DEBUG }}</p>
        '''
    else:
        template_str = '''
        <h1>Basic Debug</h1>
        <p>Info: {{ info }}</p>
        <p>Request method: {{ request.method }}</p>
        <p>Request path: {{ request.path }}</p>
        '''
    
    template = Template(template_str)
    context = Context({
        'info': info,
        'request': request,
        'settings': settings
    })
    return HttpResponse(template.render(context))

def api_data(request):
    """API endpoint that returns JSON with template processing."""
    query = request.GET.get('query', '')
    format_type = request.GET.get('format', 'json')
    
    # VULNERABLE: Template processing in API response
    template_str = '''
    API Query: {{ query }}
    Processed: {{ query|capfirst }}
    Length: {{ query|length }}
    '''
    
    template = Template(template_str)
    context = Context({'query': query})
    processed_result = template.render(context)
    
    if format_type == 'html':
        return HttpResponse(f"<pre>{processed_result}</pre>")
    else:
        return JsonResponse({
            'query': query,
            'result': processed_result,
            'status': 'success'
        })

def filter_test(request):
    """Test Django template filters with user input."""
    value = request.GET.get('value', 'test')
    filter_name = request.GET.get('filter', 'upper')
    
    # VULNERABLE: Dynamic filter application
    template_str = f'''
    <h1>Filter Test</h1>
    <p>Original: {{ value }}</p>
    <p>Filtered: {{{{ value|{filter_name} }}}}</p>
    '''
    
    template = Template(template_str)
    context = Context({'value': value})
    return HttpResponse(template.render(context))

def template_inclusion(request):
    """Test template inclusion vulnerabilities."""
    template_name = request.GET.get('template', 'default.html')
    data = request.GET.get('data', 'test data')
    
    # VULNERABLE: Dynamic template inclusion
    template_str = f'''
    <h1>Template Inclusion</h1>
    <p>Data: {{ data }}</p>
    <div>
        {{% include "{template_name}" %}}
    </div>
    '''
    
    template = Template(template_str)
    context = Context({'data': data})
    try:
        return HttpResponse(template.render(context))
    except Exception as e:
        return HttpResponse(f"Template error: {str(e)}")

def settings_access(request):
    """Test Django settings access."""
    key = request.GET.get('key', 'DEBUG')
    
    # VULNERABLE: Settings access through template
    template_str = f'''
    <h1>Settings Access</h1>
    <p>Key: {key}</p>
    <p>Value: {{{{ settings.{key} }}}}</p>
    <p>All settings available via settings object</p>
    '''
    
    template = Template(template_str)
    context = Context({'settings': settings})
    return HttpResponse(template.render(context))

def custom_context(request):
    """Test custom context processors."""
    user_input = request.GET.get('input', 'test')
    
    # VULNERABLE: Custom context with user input
    template_str = '''
    <h1>Custom Context</h1>
    <p>Input: {{ user_input }}</p>
    <p>Request User: {{ user }}</p>
    <p>Perms: {{ perms }}</p>
    <div>{% debug %}</div>
    '''
    
    template = Template(template_str)
    context = Context({
        'user_input': user_input,
        'request': request,
        'user': request.user if hasattr(request, 'user') else None,
        'perms': 'all_permissions'
    })
    return HttpResponse(template.render(context))

# URL patterns
urlpatterns = [
    path('', index, name='index'),
    path('search', search, name='search'),
    path('profile', profile, name='profile'),
    path('render', direct_render, name='render'),
    path('debug', debug_page, name='debug'),
    path('api/data', api_data, name='api_data'),
    path('filter', filter_test, name='filter'),
    path('include', template_inclusion, name='include'),
    path('settings', settings_access, name='settings'),
    path('context', custom_context, name='context'),
]

# WSGI application
application = get_wsgi_application()

if __name__ == '__main__':
    print("Starting Django Templates SSTI Test Application")
    print("WARNING: This application contains intentional vulnerabilities!")
    print("Available endpoints:")
    print("  http://localhost:8000/ - Main page")
    print("  http://localhost:8000/search?q={{7|add:'7'}} - Search test")
    print("  http://localhost:8000/profile - Profile form")
    print("  http://localhost:8000/render?content={{settings.SECRET_KEY}} - Direct render")
    print("  http://localhost:8000/debug?info={%debug%} - Debug page")
    print("  http://localhost:8000/api/data?query={{request.META}} - API endpoint")
    
    # Run development server
    from django.core.management import execute_from_command_line
    import sys
    sys.argv = ['manage.py', 'runserver', '0.0.0.0:8000']
    execute_from_command_line(sys.argv)
