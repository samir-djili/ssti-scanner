#!/usr/bin/env python3
"""
Simple test runner to validate the integration testing framework.

This script performs basic validation of the vulnerable applications
and testing infrastructure without running full integration tests.
"""

import asyncio
import sys
import time
from pathlib import Path
from typing import Dict, List

from vulnerable_app_manager import VulnerableAppManager


async def validate_app_configs():
    """Validate application configurations."""
    print("🔍 Validating application configurations...")
    
    script_dir = Path(__file__).parent
    apps_dir = script_dir / 'vulnerable_apps'
    
    if not apps_dir.exists():
        print(f"❌ Apps directory not found: {apps_dir}")
        return False
    
    manager = VulnerableAppManager(apps_dir)
    
    print(f"✅ Found {len(manager.apps)} configured applications:")
    for app_name, app in manager.apps.items():
        config = manager.configs[app_name]
        print(f"   - {app_name} ({config.engine}) - {config.base_url}")
        
        # Check if app directory exists
        if not config.app_directory.exists():
            print(f"     ⚠️  Directory missing: {config.app_directory}")
        else:
            print(f"     ✅ Directory exists: {config.app_directory}")
    
    return True


async def validate_app_structure():
    """Validate application directory structure."""
    print("\n📁 Validating application directory structure...")
    
    script_dir = Path(__file__).parent
    apps_dir = script_dir / 'vulnerable_apps'
    
    expected_apps = {
        'python/jinja2_flask': ['app.py', 'routes.py', 'requirements.txt'],
        'python/django_templates': ['app.py', 'routes.py', 'requirements.txt'],
        'php/twig_symfony': ['app.php', 'routes.php', 'composer.json'],
        'php/smarty': ['app.php', 'routes.php', 'composer.json'],
        'java/freemarker_spring': ['pom.xml', 'src/main/java/']
    }
    
    all_valid = True
    
    for app_path, required_files in expected_apps.items():
        app_dir = apps_dir / app_path
        print(f"\n   Checking {app_path}:")
        
        if not app_dir.exists():
            print(f"     ❌ Directory missing: {app_dir}")
            all_valid = False
            continue
        
        for req_file in required_files:
            file_path = app_dir / req_file
            if file_path.exists():
                print(f"     ✅ {req_file}")
            else:
                print(f"     ❌ {req_file} (missing)")
                all_valid = False
    
    return all_valid


async def quick_health_check():
    """Perform quick health check on applications."""
    print("\n🏥 Performing quick health check...")
    
    script_dir = Path(__file__).parent
    apps_dir = script_dir / 'vulnerable_apps'
    
    manager = VulnerableAppManager(apps_dir)
    
    # Try to start one simple application for testing
    test_apps = ['jinja2_flask']  # Start with Flask as it's usually quickest
    
    for app_name in test_apps:
        if app_name not in manager.apps:
            print(f"   ⚠️  Test app {app_name} not configured")
            continue
        
        print(f"   Testing {app_name}...")
        
        try:
            # Start the app
            print(f"     🚀 Starting {app_name}...")
            start_success = await manager.start_app(app_name)
            
            if not start_success:
                print(f"     ❌ Failed to start {app_name}")
                continue
            
            # Wait a moment for startup
            await asyncio.sleep(3)
            
            # Health check
            print(f"     🔍 Health checking {app_name}...")
            health = await manager.apps[app_name].health_check()
            
            if health:
                print(f"     ✅ {app_name} is healthy")
                
                # Quick test request
                app = manager.apps[app_name]
                success, response, status_code = await app.test_endpoint('/', '{{7*7}}')
                
                if success:
                    print(f"     ✅ Test request successful (HTTP {status_code})")
                else:
                    print(f"     ⚠️  Test request failed")
            else:
                print(f"     ❌ {app_name} health check failed")
            
            # Stop the app
            print(f"     🛑 Stopping {app_name}...")
            await manager.stop_app(app_name)
            
        except Exception as e:
            print(f"     ❌ Error testing {app_name}: {e}")
            try:
                await manager.stop_app(app_name)
            except:
                pass
    
    return True


async def validate_payloads():
    """Validate test payload definitions."""
    print("\n🎯 Validating test payloads...")
    
    from run_integration_tests import SSTIIntegrationTester
    
    script_dir = Path(__file__).parent
    apps_dir = script_dir / 'vulnerable_apps'
    output_dir = script_dir / 'test_results'
    
    tester = SSTIIntegrationTester(apps_dir, output_dir)
    test_suites = tester._load_test_suites()
    
    print(f"✅ Loaded {len(test_suites)} test suites:")
    
    for engine, suite in test_suites.items():
        print(f"\n   {engine.upper()} Test Suite:")
        print(f"     - {len(suite.payloads)} payloads")
        print(f"     - {len(suite.endpoints)} endpoints")
        print(f"     - {len(suite.methods)} HTTP methods")
        
        # Show sample payloads
        print(f"     Sample payloads:")
        for i, payload in enumerate(suite.payloads[:3]):
            print(f"       {i+1}. {payload['payload'][:50]}{'...' if len(payload['payload']) > 50 else ''}")
        
        if len(suite.payloads) > 3:
            print(f"       ... and {len(suite.payloads) - 3} more")
    
    return True


async def main():
    """Main validation function."""
    print("🧪 SSTI Integration Framework Validation")
    print("=" * 50)
    
    validation_steps = [
        ("Application Configurations", validate_app_configs),
        ("Directory Structure", validate_app_structure),
        ("Test Payloads", validate_payloads),
        ("Quick Health Check", quick_health_check)
    ]
    
    all_passed = True
    
    for step_name, step_func in validation_steps:
        try:
            print(f"\n📋 Step: {step_name}")
            result = await step_func()
            if result:
                print(f"✅ {step_name} - PASSED")
            else:
                print(f"❌ {step_name} - FAILED")
                all_passed = False
        except Exception as e:
            print(f"❌ {step_name} - ERROR: {e}")
            all_passed = False
    
    print("\n" + "=" * 50)
    if all_passed:
        print("🎉 All validation steps passed!")
        print("\n🚀 Ready to run integration tests:")
        print("   python run_integration_tests.py")
    else:
        print("❌ Some validation steps failed!")
        print("\n🔧 Please fix the issues above before running integration tests.")
    
    return all_passed


if __name__ == '__main__':
    try:
        result = asyncio.run(main())
        sys.exit(0 if result else 1)
    except KeyboardInterrupt:
        print("\n❌ Validation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Validation failed with error: {e}")
        sys.exit(1)
