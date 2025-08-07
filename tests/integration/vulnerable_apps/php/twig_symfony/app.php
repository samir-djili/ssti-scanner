<?php
/**
 * Vulnerable Twig/Symfony application for SSTI testing.
 *
 * This application contains intentionally vulnerable endpoints to test SSTI detection.
 * DO NOT use this code in production environments.
 */

require_once __DIR__ . '/vendor/autoload.php';

use Twig\Environment;
use Twig\Loader\ArrayLoader;
use Twig\TwigFunction;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\JsonResponse;

class TwigSSTIApp 
{
    private $twig;
    private $templates;
    
    public function __construct() 
    {
        // Define vulnerable templates
        $this->templates = [
            'index' => '
                <html>
                <head><title>Twig SSTI Test App</title></head>
                <body>
                    <h1>Twig SSTI Test Application</h1>
                    <h2>Vulnerable Endpoints:</h2>
                    <ul>
                        <li><a href="/search?q=test">Search (GET)</a></li>
                        <li><a href="/profile">Profile Form</a></li>
                        <li><a href="/render?content=hello">Direct Render</a></li>
                        <li><a href="/debug?msg=test">Debug Page</a></li>
                        <li><a href="/api/process?data=test">API Process</a></li>
                    </ul>
                    
                    <h2>Test Payloads:</h2>
                    <ul>
                        <li><code>{{7*7}}</code> - Basic math</li>
                        <li><code>{{dump(app)}}</code> - App object dump</li>
                        <li><code>{{_self}}</code> - Template self reference</li>
                        <li><code>{{"test"|upper}}</code> - Filter execution</li>
                    </ul>
                </body>
                </html>
            ',
            
            'search_results' => '
                <html>
                <head><title>Search Results</title></head>
                <body>
                    <h1>Search Results</h1>
                    <p>You searched for: {{ query }}</p>
                    <div class="results">
                        <p>Processed query: {{ query|upper }}</p>
                        <p>Query length: {{ query|length }}</p>
                    </div>
                </body>
                </html>
            ',
            
            'profile' => '
                <html>
                <body>
                    <h1>Profile Updated</h1>
                    <div class="profile">
                        <h2>{{ name }}</h2>
                        <div class="bio">{{ bio|raw }}</div>
                        <div class="signature">{{ signature }}</div>
                    </div>
                    <p>Updated at: {{ "now"|date("Y-m-d H:i:s") }}</p>
                </body>
                </html>
            ',
            
            'debug' => '
                <html>
                <body>
                    <h1>Debug Information</h1>
                    <p>Message: {{ message }}</p>
                    <div class="debug">
                        {% if show_debug %}
                            <h2>Debug Data:</h2>
                            <pre>{{ dump(app) }}</pre>
                            <pre>{{ dump(_context) }}</pre>
                        {% endif %}
                    </div>
                </body>
                </html>
            '
        ];
        
        // Initialize Twig with array loader
        $loader = new ArrayLoader($this->templates);
        $this->twig = new Environment($loader, [
            'debug' => true,
            'auto_reload' => true,
            'cache' => false
        ]);
        
        // Add debug extension
        $this->twig->addExtension(new \Twig\Extension\DebugExtension());
        
        // Add custom functions that could be exploited
        $this->twig->addFunction(new TwigFunction('system_info', function() {
            return php_uname();
        }));
        
        $this->twig->addFunction(new TwigFunction('file_contents', function($filename) {
            return file_get_contents($filename);
        }));
    }
    
    public function handleRequest() 
    {
        $request = Request::createFromGlobals();
        $path = $request->getPathInfo();
        $method = $request->getMethod();
        
        try {
            switch ($path) {
                case '/':
                    return $this->index($request);
                case '/search':
                    return $this->search($request);
                case '/profile':
                    return $this->profile($request);
                case '/render':
                    return $this->directRender($request);
                case '/debug':
                    return $this->debugPage($request);
                case '/api/process':
                    return $this->apiProcess($request);
                case '/filter':
                    return $this->filterTest($request);
                case '/include':
                    return $this->includeTest($request);
                case '/globals':
                    return $this->globalsAccess($request);
                case '/advanced':
                    return $this->advancedSSTI($request);
                default:
                    return new Response('Not Found', 404);
            }
        } catch (Exception $e) {
            return new Response('Error: ' . $e->getMessage(), 500);
        }
    }
    
    private function index($request) 
    {
        return new Response($this->twig->render('index'));
    }
    
    private function search($request) 
    {
        $query = $request->query->get('q', 'default');
        
        // VULNERABLE: Direct template rendering with user input
        return new Response($this->twig->render('search_results', [
            'query' => $query
        ]));
    }
    
    private function profile($request) 
    {
        if ($request->getMethod() === 'GET') {
            $form = '
                <html>
                <body>
                    <h1>Update Profile</h1>
                    <form method="post">
                        <label>Name:</label><br>
                        <input type="text" name="name" value="User"><br><br>
                        <label>Bio:</label><br>
                        <textarea name="bio" rows="4" cols="50">Enter bio...</textarea><br><br>
                        <label>Signature:</label><br>
                        <input type="text" name="signature" value="Best regards"><br><br>
                        <input type="submit" value="Update">
                    </form>
                </body>
                </html>
            ';
            return new Response($form);
        } else {
            $name = $request->request->get('name', 'Anonymous');
            $bio = $request->request->get('bio', 'No bio');
            $signature = $request->request->get('signature', 'No signature');
            
            // VULNERABLE: Template rendering with form data
            return new Response($this->twig->render('profile', [
                'name' => $name,
                'bio' => $bio,
                'signature' => $signature
            ]));
        }
    }
    
    private function directRender($request) 
    {
        $content = $request->query->get('content', 'hello world');
        $type = $request->query->get('type', 'simple');
        
        // VULNERABLE: Building template string from user input
        if ($type === 'math') {
            $template_str = "<h1>Math Test</h1><p>Result: $content</p>";
        } elseif ($type === 'filter') {
            $template_str = "<h1>Filter Test</h1><p>{{ \"$content\"|upper }}</p>";
        } elseif ($type === 'dump') {
            $template_str = "<h1>Dump Test</h1><p>Content: $content</p><pre>{{ dump(app) }}</pre>";
        } else {
            $template_str = "<h1>Simple</h1><p>{{ content }}</p>";
        }
        
        // Create template on the fly
        $loader = new ArrayLoader(['dynamic' => $template_str]);
        $twig = new Environment($loader);
        
        return new Response($twig->render('dynamic', ['content' => $content]));
    }
    
    private function debugPage($request) 
    {
        $message = $request->query->get('msg', 'No message');
        $level = $request->query->get('level', 'basic');
        
        // VULNERABLE: Debug information rendering
        return new Response($this->twig->render('debug', [
            'message' => $message,
            'show_debug' => ($level === 'advanced'),
            'app' => ['name' => 'TwigSSTIApp', 'version' => '1.0']
        ]));
    }
    
    private function apiProcess($request) 
    {
        $data = $request->query->get('data', '');
        $format = $request->query->get('format', 'json');
        
        // VULNERABLE: Template processing in API
        $template_str = "Processed: {{ data|upper }} (Length: {{ data|length }})";
        $loader = new ArrayLoader(['api' => $template_str]);
        $twig = new Environment($loader);
        
        $result = $twig->render('api', ['data' => $data]);
        
        if ($format === 'html') {
            return new Response("<pre>$result</pre>");
        } else {
            return new JsonResponse([
                'input' => $data,
                'result' => $result,
                'status' => 'success'
            ]);
        }
    }
    
    private function filterTest($request) 
    {
        $value = $request->query->get('value', 'test');
        $filter_name = $request->query->get('filter', 'upper');
        
        // VULNERABLE: Dynamic filter application
        $template_str = "
            <h1>Filter Test</h1>
            <p>Original: {{ value }}</p>
            <p>Filtered: {{ value|$filter_name }}</p>
        ";
        
        $loader = new ArrayLoader(['filter_test' => $template_str]);
        $twig = new Environment($loader);
        
        return new Response($twig->render('filter_test', ['value' => $value]));
    }
    
    private function includeTest($request) 
    {
        $template_name = $request->query->get('template', 'index');
        $data = $request->query->get('data', 'test data');
        
        // VULNERABLE: Dynamic template inclusion
        $template_str = "
            <h1>Include Test</h1>
            <p>Data: {{ data }}</p>
            <div>
                {% include '$template_name' %}
            </div>
        ";
        
        $loader = new ArrayLoader(['include_test' => $template_str]);
        $twig = new Environment($loader);
        
        return new Response($twig->render('include_test', ['data' => $data]));
    }
    
    private function globalsAccess($request) 
    {
        $type = $request->query->get('type', 'self');
        
        // VULNERABLE: Global object access
        if ($type === 'self') {
            $template_str = "<h1>Self Access</h1><p>{{ _self }}</p>";
        } elseif ($type === 'env') {
            $template_str = "<h1>Environment</h1><p>{{ _self.env }}</p>";
        } elseif ($type === 'context') {
            $template_str = "<h1>Context</h1><pre>{{ dump(_context) }}</pre>";
        } else {
            $template_str = "<h1>Default</h1><p>{{ app }}</p>";
        }
        
        $loader = new ArrayLoader(['globals' => $template_str]);
        $twig = new Environment($loader, ['debug' => true]);
        $twig->addExtension(new \Twig\Extension\DebugExtension());
        
        return new Response($twig->render('globals', [
            'app' => ['globals_test' => true]
        ]));
    }
    
    private function advancedSSTI($request) 
    {
        $payload = $request->query->get('payload', '{{7*7}}');
        $context = $request->query->get('context', 'simple');
        
        // VULNERABLE: Advanced SSTI scenarios
        switch ($context) {
            case 'attribute':
                $template_str = "<div data-value='$payload'>Test</div>";
                break;
            case 'javascript':
                $template_str = "<script>var test = '$payload';</script>";
                break;
            case 'css':
                $template_str = "<style>body { background: $payload; }</style>";
                break;
            default:
                $template_str = "<p>$payload</p>";
        }
        
        $loader = new ArrayLoader(['advanced' => $template_str]);
        $twig = new Environment($loader);
        
        return new Response($twig->render('advanced'));
    }
}

// Run the application
$app = new TwigSSTIApp();
$response = $app->handleRequest();
$response->send();
?>
