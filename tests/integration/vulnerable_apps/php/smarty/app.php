<?php
/**
 * Vulnerable Smarty application for SSTI testing.
 *
 * This application contains intentionally vulnerable endpoints to test SSTI detection.
 * DO NOT use this code in production environments.
 */

require_once __DIR__ . '/vendor/autoload.php';

use Smarty\Smarty;

class SmartySSTIApp 
{
    private $smarty;
    
    public function __construct() 
    {
        $this->smarty = new Smarty();
        
        // Configure Smarty
        $this->smarty->setTemplateDir(__DIR__ . '/templates/');
        $this->smarty->setCompileDir(__DIR__ . '/templates_c/');
        $this->smarty->setCacheDir(__DIR__ . '/cache/');
        $this->smarty->setConfigDir(__DIR__ . '/configs/');
        
        // Enable debugging and allow PHP functions
        $this->smarty->debugging = true;
        $this->smarty->error_reporting = E_ALL;
        
        // Register custom functions (potentially dangerous)
        $this->smarty->registerPlugin('function', 'system_exec', [$this, 'systemExec']);
        $this->smarty->registerPlugin('function', 'file_read', [$this, 'fileRead']);
        
        // Create necessary directories
        $this->createDirectories();
        $this->createTemplates();
    }
    
    private function createDirectories() 
    {
        $dirs = ['templates', 'templates_c', 'cache', 'configs'];
        foreach ($dirs as $dir) {
            if (!is_dir(__DIR__ . "/$dir")) {
                mkdir(__DIR__ . "/$dir", 0755, true);
            }
        }
    }
    
    private function createTemplates() 
    {
        $templates = [
            'index.tpl' => '
                <html>
                <head><title>Smarty SSTI Test App</title></head>
                <body>
                    <h1>Smarty SSTI Test Application</h1>
                    <h2>Vulnerable Endpoints:</h2>
                    <ul>
                        <li><a href="/search?q=test">Search (GET)</a></li>
                        <li><a href="/profile">Profile Form</a></li>
                        <li><a href="/render?content=hello">Direct Render</a></li>
                        <li><a href="/debug?info=test">Debug Page</a></li>
                        <li><a href="/api/calc?expr=test">API Calculator</a></li>
                    </ul>
                    
                    <h2>Test Payloads:</h2>
                    <ul>
                        <li><code>{7*7}</code> - Basic math</li>
                        <li><code>{math equation="7*7"}</code> - Math function</li>
                        <li><code>{$smarty.server}</code> - Server variables</li>
                        <li><code>{php}phpinfo();{/php}</code> - PHP execution</li>
                    </ul>
                </body>
                </html>
            ',
            
            'search.tpl' => '
                <html>
                <head><title>Search Results</title></head>
                <body>
                    <h1>Search Results</h1>
                    <p>You searched for: {$query}</p>
                    <div class="results">
                        <p>Processed: {$query|upper}</p>
                        <p>Length: {$query|count_characters}</p>
                        <p>Math test: {7*7}</p>
                    </div>
                </body>
                </html>
            ',
            
            'profile.tpl' => '
                <html>
                <body>
                    <h1>Profile Updated</h1>
                    <div class="profile">
                        <h2>{$name}</h2>
                        <div class="bio">{$bio}</div>
                        <div class="signature">{$signature}</div>
                    </div>
                    <p>Server: {$smarty.server.SERVER_NAME}</p>
                    <p>Updated: {$smarty.now|date_format:"%Y-%m-%d %H:%M:%S"}</p>
                </body>
                </html>
            ',
            
            'debug.tpl' => '
                <html>
                <body>
                    <h1>Debug Information</h1>
                    <p>Info: {$info}</p>
                    <div class="debug">
                        {if $show_debug}
                            <h2>Server Info:</h2>
                            <pre>{$smarty.server|@print_r}</pre>
                            <h2>Constants:</h2>
                            <pre>{$smarty.const.PHP_VERSION}</pre>
                        {/if}
                    </div>
                </body>
                </html>
            '
        ];
        
        foreach ($templates as $filename => $content) {
            file_put_contents(__DIR__ . "/templates/$filename", $content);
        }
    }
    
    public function systemExec($params, $smarty) 
    {
        $command = $params['command'] ?? 'echo "No command"';
        return shell_exec($command);
    }
    
    public function fileRead($params, $smarty) 
    {
        $filename = $params['file'] ?? '/etc/passwd';
        return file_get_contents($filename);
    }
    
    public function handleRequest() 
    {
        $path = $_SERVER['REQUEST_URI'] ?? '/';
        $path = parse_url($path, PHP_URL_PATH);
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        
        try {
            switch ($path) {
                case '/':
                    return $this->index();
                case '/search':
                    return $this->search();
                case '/profile':
                    return $this->profile();
                case '/render':
                    return $this->directRender();
                case '/debug':
                    return $this->debugPage();
                case '/api/calc':
                    return $this->apiCalculator();
                case '/math':
                    return $this->mathTest();
                case '/server':
                    return $this->serverInfo();
                case '/php':
                    return $this->phpExecution();
                case '/custom':
                    return $this->customFunction();
                default:
                    http_response_code(404);
                    return 'Not Found';
            }
        } catch (Exception $e) {
            http_response_code(500);
            return 'Error: ' . $e->getMessage();
        }
    }
    
    private function index() 
    {
        return $this->smarty->fetch('index.tpl');
    }
    
    private function search() 
    {
        $query = $_GET['q'] ?? 'default';
        
        // VULNERABLE: Direct assignment to template
        $this->smarty->assign('query', $query);
        return $this->smarty->fetch('search.tpl');
    }
    
    private function profile() 
    {
        if ($_SERVER['REQUEST_METHOD'] === 'GET') {
            return '
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
        } else {
            $name = $_POST['name'] ?? 'Anonymous';
            $bio = $_POST['bio'] ?? 'No bio';
            $signature = $_POST['signature'] ?? 'No signature';
            
            // VULNERABLE: Template variables from form data
            $this->smarty->assign('name', $name);
            $this->smarty->assign('bio', $bio);
            $this->smarty->assign('signature', $signature);
            
            return $this->smarty->fetch('profile.tpl');
        }
    }
    
    private function directRender() 
    {
        $content = $_GET['content'] ?? 'hello world';
        $type = $_GET['type'] ?? 'simple';
        
        // VULNERABLE: Building template string from user input
        if ($type === 'math') {
            $template_content = "<h1>Math Test</h1><p>{math equation=\"$content\"}</p>";
        } elseif ($type === 'server') {
            $template_content = "<h1>Server Test</h1><p>Content: $content</p><p>Server: {\$smarty.server.HTTP_HOST}</p>";
        } elseif ($type === 'php') {
            $template_content = "<h1>PHP Test</h1><p>Content: $content</p><p>{php}echo '$content';{/php}</p>";
        } else {
            $template_content = "<h1>Simple</h1><p>{\$content}</p>";
        }
        
        // Write dynamic template
        file_put_contents(__DIR__ . '/templates/dynamic.tpl', $template_content);
        $this->smarty->assign('content', $content);
        
        return $this->smarty->fetch('dynamic.tpl');
    }
    
    private function debugPage() 
    {
        $info = $_GET['info'] ?? 'No info';
        $level = $_GET['level'] ?? 'basic';
        
        // VULNERABLE: Debug information
        $this->smarty->assign('info', $info);
        $this->smarty->assign('show_debug', ($level === 'advanced'));
        
        return $this->smarty->fetch('debug.tpl');
    }
    
    private function apiCalculator() 
    {
        $expr = $_GET['expr'] ?? '1+1';
        $format = $_GET['format'] ?? 'json';
        
        // VULNERABLE: Math expression evaluation
        $template_content = "{math equation=\"$expr\"}";
        file_put_contents(__DIR__ . '/templates/calc.tpl', $template_content);
        
        $result = $this->smarty->fetch('calc.tpl');
        
        if ($format === 'html') {
            return "<h1>Calculator</h1><p>Expression: $expr</p><p>Result: $result</p>";
        } else {
            header('Content-Type: application/json');
            return json_encode([
                'expression' => $expr,
                'result' => trim($result),
                'status' => 'success'
            ]);
        }
    }
    
    private function mathTest() 
    {
        $equation = $_GET['eq'] ?? '7*7';
        
        // VULNERABLE: Direct math function usage
        $template_content = "
            <h1>Math Test</h1>
            <p>Equation: $equation</p>
            <p>Result: {math equation=\"$equation\"}</p>
            <p>Simple: {$equation}</p>
        ";
        
        file_put_contents(__DIR__ . '/templates/math.tpl', $template_content);
        return $this->smarty->fetch('math.tpl');
    }
    
    private function serverInfo() 
    {
        $key = $_GET['key'] ?? 'HTTP_HOST';
        
        // VULNERABLE: Server variable access
        $template_content = "
            <h1>Server Info</h1>
            <p>Key: $key</p>
            <p>Value: {\$smarty.server.$key}</p>
            <p>All SERVER vars: {\$smarty.server|@print_r}</p>
        ";
        
        file_put_contents(__DIR__ . '/templates/server.tpl', $template_content);
        return $this->smarty->fetch('server.tpl');
    }
    
    private function phpExecution() 
    {
        $code = $_GET['code'] ?? 'phpinfo()';
        
        // VULNERABLE: PHP code execution
        $template_content = "
            <h1>PHP Execution</h1>
            <p>Code: $code</p>
            <div>{php}$code;{/php}</div>
        ";
        
        file_put_contents(__DIR__ . '/templates/php_exec.tpl', $template_content);
        return $this->smarty->fetch('php_exec.tpl');
    }
    
    private function customFunction() 
    {
        $command = $_GET['cmd'] ?? 'whoami';
        $file = $_GET['file'] ?? '/etc/passwd';
        $action = $_GET['action'] ?? 'exec';
        
        // VULNERABLE: Custom function calls
        if ($action === 'exec') {
            $template_content = "<h1>Command Execution</h1><p>{system_exec command=\"$command\"}</p>";
        } else {
            $template_content = "<h1>File Read</h1><pre>{file_read file=\"$file\"}</pre>";
        }
        
        file_put_contents(__DIR__ . '/templates/custom.tpl', $template_content);
        return $this->smarty->fetch('custom.tpl');
    }
}

// Run the application
$app = new SmartySSTIApp();
echo $app->handleRequest();
?>
