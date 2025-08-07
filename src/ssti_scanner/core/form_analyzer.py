"""
Form Analyzer for SSTI Scanner.

This module provides form analysis capabilities to identify injection points
and analyze web forms for SSTI vulnerability testing.
"""

import logging
import re
from typing import List, Dict, Any, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup, Tag
import aiohttp


class FormAnalyzer:
    """
    Analyzes web forms and identifies potential injection points for SSTI testing.
    
    This class provides:
    1. Form discovery and parsing
    2. Input field analysis
    3. Injection point identification
    4. Parameter extraction and categorization
    """
    
    def __init__(self, session: Optional[aiohttp.ClientSession] = None):
        """
        Initialize the form analyzer.
        
        Args:
            session: HTTP session for making requests
        """
        self.logger = logging.getLogger(__name__)
        self.session = session
        self.discovered_forms = []
        self.injection_points = {}
        
    async def analyze_page(self, url: str, content: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze a web page for forms and injection points.
        
        Args:
            url: URL of the page to analyze
            content: HTML content (if None, will fetch from URL)
            
        Returns:
            Analysis results including forms and injection points
        """
        if content is None:
            content = await self._fetch_page_content(url)
            
        if not content:
            return {'forms': [], 'injection_points': [], 'errors': ['Failed to fetch content']}
            
        # Parse HTML content
        soup = BeautifulSoup(content, 'html.parser')
        
        # Analyze forms
        forms = self._analyze_forms(soup, url)
        
        # Find URL parameters
        url_params = self._extract_url_parameters(url)
        
        # Identify injection points
        injection_points = self._identify_injection_points(forms, url_params)
        
        # Analyze input patterns
        input_patterns = self._analyze_input_patterns(soup)
        
        result = {
            'url': url,
            'forms': forms,
            'url_parameters': url_params,
            'injection_points': injection_points,
            'input_patterns': input_patterns,
            'total_forms': len(forms),
            'total_injection_points': len(injection_points)
        }
        
        self.logger.info(
            f"Analyzed {url}: Found {len(forms)} forms and "
            f"{len(injection_points)} injection points"
        )
        
        return result
    
    def _analyze_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict[str, Any]]:
        """
        Extract and analyze all forms from the HTML.
        
        Args:
            soup: BeautifulSoup object of the HTML
            base_url: Base URL for resolving relative form actions
            
        Returns:
            List of form analysis results
        """
        forms = []
        
        for form_tag in soup.find_all('form'):
            form_info = self._parse_form(form_tag, base_url)
            if form_info:
                forms.append(form_info)
                
        return forms
    
    def _parse_form(self, form_tag: Tag, base_url: str) -> Optional[Dict[str, Any]]:
        """
        Parse a single form element.
        
        Args:
            form_tag: BeautifulSoup form tag
            base_url: Base URL for resolving relative actions
            
        Returns:
            Form information dictionary
        """
        try:
            # Extract form attributes
            action = form_tag.get('action', '')
            method = form_tag.get('method', 'GET').upper()
            enctype = form_tag.get('enctype', 'application/x-www-form-urlencoded')
            
            # Resolve relative action URLs
            if action:
                action = urljoin(base_url, action)
            else:
                action = base_url
                
            # Extract form inputs
            inputs = self._extract_form_inputs(form_tag)
            
            # Analyze form characteristics
            characteristics = self._analyze_form_characteristics(form_tag, inputs)
            
            form_info = {
                'action': action,
                'method': method,
                'enctype': enctype,
                'inputs': inputs,
                'characteristics': characteristics,
                'total_inputs': len(inputs),
                'text_inputs': len([i for i in inputs if i['type'] in ['text', 'search', 'url', 'email']]),
                'textarea_inputs': len([i for i in inputs if i['type'] == 'textarea']),
                'hidden_inputs': len([i for i in inputs if i['type'] == 'hidden']),
                'vulnerable_inputs': len([i for i in inputs if i.get('potentially_vulnerable', False)])
            }
            
            return form_info
            
        except Exception as e:
            self.logger.error(f"Error parsing form: {e}")
            return None
    
    def _extract_form_inputs(self, form_tag: Tag) -> List[Dict[str, Any]]:
        """
        Extract all input fields from a form.
        
        Args:
            form_tag: BeautifulSoup form tag
            
        Returns:
            List of input field information
        """
        inputs = []
        
        # Find all input elements
        for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
            input_info = self._parse_input_field(input_tag)
            if input_info:
                inputs.append(input_info)
                
        return inputs
    
    def _parse_input_field(self, input_tag: Tag) -> Optional[Dict[str, Any]]:
        """
        Parse a single input field.
        
        Args:
            input_tag: BeautifulSoup input tag
            
        Returns:
            Input field information
        """
        try:
            tag_name = input_tag.name.lower()
            input_type = input_tag.get('type', 'text').lower()
            name = input_tag.get('name', '')
            value = input_tag.get('value', '')
            placeholder = input_tag.get('placeholder', '')
            required = input_tag.has_attr('required')
            
            # Handle different input types
            if tag_name == 'textarea':
                input_type = 'textarea'
                value = input_tag.get_text(strip=True)
            elif tag_name == 'select':
                input_type = 'select'
                options = [opt.get('value', opt.get_text(strip=True)) 
                          for opt in input_tag.find_all('option')]
                value = options
                
            # Determine if potentially vulnerable to SSTI
            potentially_vulnerable = self._is_potentially_vulnerable_input(
                input_type, name, placeholder
            )
            
            # Analyze input patterns
            patterns = self._analyze_input_field_patterns(input_tag)
            
            input_info = {
                'tag': tag_name,
                'type': input_type,
                'name': name,
                'value': value,
                'placeholder': placeholder,
                'required': required,
                'potentially_vulnerable': potentially_vulnerable,
                'patterns': patterns,
                'attributes': dict(input_tag.attrs)
            }
            
            return input_info
            
        except Exception as e:
            self.logger.error(f"Error parsing input field: {e}")
            return None
    
    def _is_potentially_vulnerable_input(self, input_type: str, name: str, placeholder: str) -> bool:
        """
        Determine if an input field is potentially vulnerable to SSTI.
        
        Args:
            input_type: Type of the input field
            name: Name attribute
            placeholder: Placeholder text
            
        Returns:
            True if potentially vulnerable
        """
        # Input types that can be vulnerable
        vulnerable_types = ['text', 'textarea', 'search', 'url', 'email', 'hidden']
        
        if input_type not in vulnerable_types:
            return False
            
        # Check for template-related field names
        template_indicators = [
            'template', 'message', 'content', 'body', 'text', 'comment',
            'description', 'email_body', 'subject', 'title', 'name',
            'search', 'query', 'filter', 'value', 'data'
        ]
        
        name_lower = name.lower()
        placeholder_lower = placeholder.lower()
        
        # Check name attribute
        for indicator in template_indicators:
            if indicator in name_lower or indicator in placeholder_lower:
                return True
                
        # Check for common vulnerable parameter patterns
        vulnerable_patterns = [
            r'.*template.*', r'.*message.*', r'.*content.*', r'.*body.*',
            r'.*text.*', r'.*comment.*', r'.*desc.*', r'.*subject.*'
        ]
        
        for pattern in vulnerable_patterns:
            if re.search(pattern, name_lower) or re.search(pattern, placeholder_lower):
                return True
                
        return False
    
    def _analyze_form_characteristics(self, form_tag: Tag, inputs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze form characteristics for SSTI vulnerability assessment.
        
        Args:
            form_tag: BeautifulSoup form tag
            inputs: List of parsed input fields
            
        Returns:
            Form characteristics analysis
        """
        characteristics = {
            'has_file_upload': False,
            'has_csrf_protection': False,
            'has_template_fields': False,
            'has_rich_text_editor': False,
            'form_purpose': 'unknown',
            'risk_level': 'low'
        }
        
        # Check for file upload
        file_inputs = [i for i in inputs if i['type'] == 'file']
        characteristics['has_file_upload'] = len(file_inputs) > 0
        
        # Check for CSRF tokens
        csrf_inputs = [
            i for i in inputs 
            if 'csrf' in i['name'].lower() or 'token' in i['name'].lower()
        ]
        characteristics['has_csrf_protection'] = len(csrf_inputs) > 0
        
        # Check for template-related fields
        template_fields = [i for i in inputs if i.get('potentially_vulnerable', False)]
        characteristics['has_template_fields'] = len(template_fields) > 0
        
        # Check for rich text editors
        rich_text_indicators = ['ckeditor', 'tinymce', 'wysiwyg', 'editor']
        form_html = str(form_tag)
        for indicator in rich_text_indicators:
            if indicator in form_html.lower():
                characteristics['has_rich_text_editor'] = True
                break
                
        # Determine form purpose
        characteristics['form_purpose'] = self._determine_form_purpose(inputs, form_tag)
        
        # Calculate risk level
        characteristics['risk_level'] = self._calculate_risk_level(characteristics, inputs)
        
        return characteristics
    
    def _determine_form_purpose(self, inputs: List[Dict[str, Any]], form_tag: Tag) -> str:
        """
        Determine the purpose of the form based on inputs and context.
        
        Args:
            inputs: List of input fields
            form_tag: BeautifulSoup form tag
            
        Returns:
            Form purpose classification
        """
        input_names = [i['name'].lower() for i in inputs if i['name']]
        form_text = form_tag.get_text().lower()
        
        # Login form
        if any(name in input_names for name in ['username', 'password', 'email']):
            if 'password' in input_names:
                return 'login'
                
        # Registration form
        if any(name in input_names for name in ['register', 'signup']):
            return 'registration'
            
        # Contact form
        if any(name in input_names for name in ['message', 'subject', 'email']):
            if 'message' in input_names or 'contact' in form_text:
                return 'contact'
                
        # Search form
        if any(name in input_names for name in ['search', 'query', 'q']):
            return 'search'
            
        # Comment form
        if any(name in input_names for name in ['comment', 'content', 'body']):
            return 'comment'
            
        # Admin/CMS form
        if any(name in input_names for name in ['template', 'config', 'admin']):
            return 'admin'
            
        # Email form
        if any(name in input_names for name in ['email_body', 'email_template', 'subject']):
            return 'email'
            
        return 'unknown'
    
    def _calculate_risk_level(self, characteristics: Dict[str, Any], 
                            inputs: List[Dict[str, Any]]) -> str:
        """
        Calculate risk level for SSTI vulnerabilities.
        
        Args:
            characteristics: Form characteristics
            inputs: List of input fields
            
        Returns:
            Risk level ('low', 'medium', 'high', 'critical')
        """
        risk_score = 0
        
        # Base risk from form purpose
        purpose_risk = {
            'admin': 3,
            'email': 3,
            'comment': 2,
            'contact': 2,
            'unknown': 1,
            'search': 1,
            'login': 0,
            'registration': 1
        }
        
        risk_score += purpose_risk.get(characteristics['form_purpose'], 1)
        
        # Additional risk factors
        if characteristics['has_template_fields']:
            risk_score += 2
            
        if characteristics['has_rich_text_editor']:
            risk_score += 1
            
        if not characteristics['has_csrf_protection']:
            risk_score += 1
            
        # High-risk input fields
        vulnerable_inputs = [i for i in inputs if i.get('potentially_vulnerable', False)]
        risk_score += min(len(vulnerable_inputs), 3)
        
        # Convert score to risk level
        if risk_score >= 6:
            return 'critical'
        elif risk_score >= 4:
            return 'high'
        elif risk_score >= 2:
            return 'medium'
        else:
            return 'low'
    
    def _extract_url_parameters(self, url: str) -> Dict[str, str]:
        """
        Extract parameters from URL query string.
        
        Args:
            url: URL to analyze
            
        Returns:
            Dictionary of URL parameters
        """
        try:
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            
            # Convert list values to single values
            result = {}
            for key, values in params.items():
                if values:
                    result[key] = values[0]
                    
            return result
            
        except Exception as e:
            self.logger.error(f"Error extracting URL parameters: {e}")
            return {}
    
    def _identify_injection_points(self, forms: List[Dict[str, Any]], 
                                 url_params: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Identify potential injection points from forms and URL parameters.
        
        Args:
            forms: List of analyzed forms
            url_params: URL parameters
            
        Returns:
            List of injection points
        """
        injection_points = []
        
        # Add URL parameters as injection points
        for param_name, param_value in url_params.items():
            injection_point = {
                'type': 'url_parameter',
                'name': param_name,
                'value': param_value,
                'method': 'GET',
                'potentially_vulnerable': self._is_potentially_vulnerable_input(
                    'text', param_name, ''
                ),
                'risk_level': 'medium' if 'template' in param_name.lower() else 'low'
            }
            injection_points.append(injection_point)
            
        # Add form inputs as injection points
        for form in forms:
            for input_field in form['inputs']:
                if input_field.get('potentially_vulnerable', False):
                    injection_point = {
                        'type': 'form_input',
                        'form_action': form['action'],
                        'form_method': form['method'],
                        'name': input_field['name'],
                        'value': input_field['value'],
                        'input_type': input_field['type'],
                        'method': form['method'],
                        'potentially_vulnerable': True,
                        'risk_level': form['characteristics']['risk_level']
                    }
                    injection_points.append(injection_point)
                    
        return injection_points
    
    def _analyze_input_patterns(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """
        Analyze input patterns that might indicate template usage.
        
        Args:
            soup: BeautifulSoup object of the HTML
            
        Returns:
            Pattern analysis results
        """
        patterns = {
            'template_syntax_found': False,
            'javascript_templates': False,
            'server_side_includes': False,
            'suspicious_patterns': []
        }
        
        html_content = str(soup)
        
        # Check for template syntax in HTML
        template_patterns = [
            r'\{\{.*?\}\}',  # Handlebars, Jinja2, Twig
            r'\{%.*?%\}',    # Jinja2, Twig, Django
            r'\$\{.*?\}',    # Freemarker, Velocity
            r'<#.*?#>',      # Freemarker
            r'\{.*?\}',      # Smarty, Velocity
            r'<%.*?%>',      # ERB, JSP
            r'<!--#.*?-->'   # Server Side Includes
        ]
        
        for pattern in template_patterns:
            matches = re.findall(pattern, html_content, re.DOTALL)
            if matches:
                patterns['template_syntax_found'] = True
                patterns['suspicious_patterns'].extend(matches[:5])  # Limit to 5 examples
                
        # Check for JavaScript template libraries
        js_template_indicators = [
            'handlebars', 'mustache', 'underscore', 'lodash', 'backbone'
        ]
        
        for indicator in js_template_indicators:
            if indicator in html_content.lower():
                patterns['javascript_templates'] = True
                break
                
        # Check for Server Side Includes
        if '<!--#' in html_content:
            patterns['server_side_includes'] = True
            
        return patterns
    
    def _analyze_input_field_patterns(self, input_tag: Tag) -> Dict[str, Any]:
        """
        Analyze patterns in individual input fields.
        
        Args:
            input_tag: BeautifulSoup input tag
            
        Returns:
            Pattern analysis for the input field
        """
        patterns = {
            'has_validation': False,
            'has_length_limit': False,
            'accepts_html': False,
            'suspicious_attributes': []
        }
        
        # Check for validation attributes
        validation_attrs = ['pattern', 'min', 'max', 'minlength', 'maxlength', 'required']
        for attr in validation_attrs:
            if input_tag.has_attr(attr):
                patterns['has_validation'] = True
                break
                
        # Check for length limits
        if input_tag.has_attr('maxlength'):
            patterns['has_length_limit'] = True
            
        # Check if field might accept HTML
        field_classes = input_tag.get('class', [])
        field_id = input_tag.get('id', '')
        
        html_indicators = ['wysiwyg', 'editor', 'rich', 'html', 'content']
        for indicator in html_indicators:
            if (any(indicator in cls.lower() for cls in field_classes) or 
                indicator in field_id.lower()):
                patterns['accepts_html'] = True
                break
                
        # Check for suspicious attributes
        suspicious_attrs = []
        for attr, value in input_tag.attrs.items():
            if attr.lower() in ['onclick', 'onchange', 'onfocus', 'onblur']:
                suspicious_attrs.append(f"{attr}={value}")
                
        patterns['suspicious_attributes'] = suspicious_attrs
        
        return patterns
    
    async def _fetch_page_content(self, url: str) -> Optional[str]:
        """
        Fetch content from a URL.
        
        Args:
            url: URL to fetch
            
        Returns:
            HTML content or None if failed
        """
        if not self.session:
            return None
            
        try:
            async with self.session.get(
                url, 
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status == 200:
                    return await response.text()
                    
        except Exception as e:
            self.logger.error(f"Failed to fetch {url}: {e}")
            
        return None
    
    def get_high_risk_injection_points(self, analysis_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Filter injection points to get only high-risk ones.
        
        Args:
            analysis_result: Result from analyze_page
            
        Returns:
            List of high-risk injection points
        """
        injection_points = analysis_result.get('injection_points', [])
        
        high_risk = [
            point for point in injection_points
            if (point.get('risk_level') in ['high', 'critical'] and
                point.get('potentially_vulnerable', False))
        ]
        
        return high_risk
    
    def suggest_test_parameters(self, analysis_result: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Suggest parameters to test based on form analysis.
        
        Args:
            analysis_result: Result from analyze_page
            
        Returns:
            Dictionary of suggested test parameters by category
        """
        suggestions = {
            'high_priority': [],
            'medium_priority': [],
            'low_priority': []
        }
        
        injection_points = analysis_result.get('injection_points', [])
        
        for point in injection_points:
            param_name = point.get('name', '')
            risk_level = point.get('risk_level', 'low')
            
            if risk_level in ['critical', 'high']:
                suggestions['high_priority'].append(param_name)
            elif risk_level == 'medium':
                suggestions['medium_priority'].append(param_name)
            else:
                suggestions['low_priority'].append(param_name)
                
        # Remove duplicates
        for category in suggestions:
            suggestions[category] = list(set(suggestions[category]))
            
        return suggestions
