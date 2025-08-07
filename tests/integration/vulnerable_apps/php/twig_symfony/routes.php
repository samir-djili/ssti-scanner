<?php
/**
 * Route configuration for Twig SSTI test application.
 */

class TwigRoutes 
{
    const VULNERABLE_ROUTES = [
        'search' => [
            'url' => '/search',
            'methods' => ['GET'],
            'parameters' => ['q'],
            'vulnerability_type' => 'reflected_parameter',
            'payload_location' => 'query_parameter',
            'confidence' => 'high',
            'description' => 'Search query parameter rendered through Twig template'
        ],
        
        'profile_form' => [
            'url' => '/profile',
            'methods' => ['GET', 'POST'],
            'parameters' => ['name', 'bio', 'signature'],
            'vulnerability_type' => 'form_input',
            'payload_location' => 'form_data',
            'confidence' => 'high',
            'description' => 'Form data rendered through Twig with raw filter'
        ],
        
        'direct_render' => [
            'url' => '/render',
            'methods' => ['GET'],
            'parameters' => ['content', 'type'],
            'vulnerability_type' => 'template_injection',
            'payload_location' => 'query_parameter',
            'confidence' => 'high',
            'description' => 'Direct template string construction from user input'
        ],
        
        'debug_page' => [
            'url' => '/debug',
            'methods' => ['GET'],
            'parameters' => ['msg', 'level'],
            'vulnerability_type' => 'debug_information',
            'payload_location' => 'query_parameter',
            'confidence' => 'high',
            'description' => 'Debug page with dump() function and context access'
        ],
        
        'api_process' => [
            'url' => '/api/process',
            'methods' => ['GET'],
            'parameters' => ['data', 'format'],
            'vulnerability_type' => 'api_response',
            'payload_location' => 'query_parameter',
            'confidence' => 'medium',
            'description' => 'API endpoint with template processing'
        ],
        
        'filter_test' => [
            'url' => '/filter',
            'methods' => ['GET'],
            'parameters' => ['value', 'filter'],
            'vulnerability_type' => 'filter_injection',
            'payload_location' => 'query_parameter',
            'confidence' => 'high',
            'description' => 'Dynamic Twig filter application'
        ],
        
        'include_test' => [
            'url' => '/include',
            'methods' => ['GET'],
            'parameters' => ['template', 'data'],
            'vulnerability_type' => 'template_inclusion',
            'payload_location' => 'query_parameter',
            'confidence' => 'medium',
            'description' => 'Dynamic template inclusion vulnerability'
        ],
        
        'globals_access' => [
            'url' => '/globals',
            'methods' => ['GET'],
            'parameters' => ['type'],
            'vulnerability_type' => 'globals_access',
            'payload_location' => 'query_parameter',
            'confidence' => 'high',
            'description' => 'Twig global objects access (_self, _context, _env)'
        ],
        
        'advanced_ssti' => [
            'url' => '/advanced',
            'methods' => ['GET'],
            'parameters' => ['payload', 'context'],
            'vulnerability_type' => 'context_injection',
            'payload_location' => 'query_parameter',
            'confidence' => 'high',
            'description' => 'Advanced SSTI in different contexts (HTML, JS, CSS)'
        ]
    ];
    
    const SAFE_ROUTES = [
        'index' => [
            'url' => '/',
            'methods' => ['GET'],
            'description' => 'Main index page - static content'
        ]
    ];
    
    // Test payloads specific to Twig
    const TWIG_TEST_PAYLOADS = [
        'basic_math' => [
            'payload' => '{{7*7}}',
            'expected_response' => '49',
            'confidence' => 'high',
            'description' => 'Basic mathematical operation'
        ],
        
        'string_multiplication' => [
            'payload' => '{{7*"7"}}',
            'expected_response' => '7777777',
            'confidence' => 'high',
            'description' => 'String multiplication'
        ],
        
        'filter_upper' => [
            'payload' => '{{"test"|upper}}',
            'expected_response' => 'TEST',
            'confidence' => 'high',
            'description' => 'String uppercase filter'
        ],
        
        'filter_length' => [
            'payload' => '{{"test"|length}}',
            'expected_response' => '4',
            'confidence' => 'medium',
            'description' => 'String length filter'
        ],
        
        'dump_function' => [
            'payload' => '{{dump(app)}}',
            'expected_response' => 'array',
            'confidence' => 'high',
            'description' => 'Dump function revealing internal objects'
        ],
        
        'self_reference' => [
            'payload' => '{{_self}}',
            'expected_response' => 'Template',
            'confidence' => 'high',
            'description' => 'Template self reference'
        ],
        
        'environment_access' => [
            'payload' => '{{_self.env}}',
            'expected_response' => 'Twig\\Environment',
            'confidence' => 'high',
            'description' => 'Twig environment object access'
        ],
        
        'context_dump' => [
            'payload' => '{{dump(_context)}}',
            'expected_response' => 'array',
            'confidence' => 'high',
            'description' => 'Template context dump'
        ],
        
        'date_function' => [
            'payload' => '{{"now"|date("Y")}}',
            'expected_response' => '20',
            'confidence' => 'medium',
            'description' => 'Date function execution'
        ],
        
        'range_function' => [
            'payload' => '{{range(1,3)|join(",")}}',
            'expected_response' => '1,2,3',
            'confidence' => 'medium',
            'description' => 'Range and join functions'
        ],
        
        'advanced_math' => [
            'payload' => '{{(7*7)|abs}}',
            'expected_response' => '49',
            'confidence' => 'high',
            'description' => 'Mathematical operation with filter chain'
        ],
        
        'conditional_output' => [
            'payload' => '{% if 7*7 == 49 %}MATCH{% endif %}',
            'expected_response' => 'MATCH',
            'confidence' => 'high',
            'description' => 'Conditional template tag with math'
        ]
    ];
    
    // Context-specific payloads for Twig
    const CONTEXT_PAYLOADS = [
        'html_context' => [
            '{{7*7}}',
            '{{dump(app)}}',
            '{{_self}}'
        ],
        
        'url_parameter' => [
            '%7B%7B7*7%7D%7D',  // URL encoded {{7*7}}
            '{{7*7}}',
            '{{"test"|upper}}'
        ],
        
        'form_data' => [
            '{{7*7}}',
            '{{dump(_context)}}',
            '{{_self.env}}'
        ],
        
        'json_context' => [
            '{{7*7}}',
            '{{dump(app)}}'
        ],
        
        'attribute_context' => [
            '{{7*7}}',
            '{{_self}}'
        ],
        
        'javascript_context' => [
            '\'; {{7*7}}; //',
            '{{7*7}}',
        ],
        
        'css_context' => [
            '{{7*7}}px',
            '{{7*7}}'
        ]
    ];
    
    // Expected error patterns for Twig
    const TWIG_ERROR_PATTERNS = [
        'Twig\\Error\\SyntaxError',
        'Twig\\Error\\RuntimeError',
        'Twig_Error_Syntax',
        'Twig_Error_Runtime',
        'Unknown filter',
        'Unknown function',
        'Unexpected token'
    ];
    
    // Twig-specific indicators
    const TWIG_INDICATORS = [
        'Twig\\Environment',
        'Twig\\Template',
        'Twig_',
        'dump()',
        '_self',
        '_context',
        'Symfony'
    ];
    
    // Test configuration
    const TEST_CONFIG = [
        'app_name' => 'twig_symfony',
        'host' => 'localhost',
        'port' => 8080,
        'base_url' => 'http://localhost:8080',
        'startup_timeout' => 10,
        'request_timeout' => 5,
        'expected_engine' => 'twig',
        'framework' => 'symfony',
        'language' => 'php'
    ];
}
?>
