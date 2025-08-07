"""
Integration test framework for vulnerable web applications.

This module provides functionality to start, stop, and test vulnerable web applications
across different template engines for SSTI detection testing.
"""

import asyncio
import subprocess
import time
import signal
import os
import sys
import json
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from abc import ABC, abstractmethod

import requests
import psutil


@dataclass
class AppConfig:
    """Configuration for a vulnerable application."""
    name: str
    engine: str
    language: str
    framework: str
    host: str
    port: int
    startup_command: List[str]
    startup_timeout: int
    health_check_url: str
    base_url: str
    app_directory: Path
    routes_config: Dict[str, Any]
    test_payloads: Dict[str, Any]


class VulnerableApp(ABC):
    """Abstract base class for vulnerable applications."""
    
    def __init__(self, config: AppConfig):
        self.config = config
        self.process: Optional[subprocess.Popen] = None
        self.is_running = False
    
    @abstractmethod
    async def start(self) -> bool:
        """Start the vulnerable application."""
        pass
    
    @abstractmethod
    async def stop(self) -> bool:
        """Stop the vulnerable application."""
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the application is healthy."""
        pass
    
    async def test_endpoint(self, endpoint: str, payload: str, method: str = 'GET', 
                          data: Dict[str, str] = None) -> Tuple[bool, str, int]:
        """Test an endpoint with a payload."""
        url = f"{self.config.base_url}{endpoint}"
        
        try:
            if method.upper() == 'GET':
                response = requests.get(url, params={'q': payload}, timeout=5)
            elif method.upper() == 'POST':
                form_data = data or {}
                form_data['q'] = payload
                response = requests.post(url, data=form_data, timeout=5)
            else:
                return False, f"Unsupported method: {method}", 0
            
            return True, response.text, response.status_code
            
        except Exception as e:
            return False, str(e), 0


class PythonFlaskApp(VulnerableApp):
    """Flask application runner."""
    
    async def start(self) -> bool:
        """Start Flask application."""
        try:
            # Change to app directory
            os.chdir(self.config.app_directory)
            
            # Install dependencies
            subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'], 
                          check=True, capture_output=True)
            
            # Start the application
            self.process = subprocess.Popen(
                [sys.executable, 'app.py'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.config.app_directory
            )
            
            # Wait for startup
            await self._wait_for_startup()
            
            self.is_running = True
            return True
            
        except Exception as e:
            print(f"Failed to start Flask app {self.config.name}: {e}")
            return False
    
    async def stop(self) -> bool:
        """Stop Flask application."""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
            
            self.is_running = False
            return True
        return False
    
    async def health_check(self) -> bool:
        """Check Flask application health."""
        try:
            response = requests.get(self.config.health_check_url, timeout=5)
            return response.status_code == 200
        except:
            return False
    
    async def _wait_for_startup(self):
        """Wait for Flask application to start."""
        for _ in range(self.config.startup_timeout):
            if await self.health_check():
                return
            await asyncio.sleep(1)
        raise TimeoutError(f"Flask app {self.config.name} failed to start")


class PythonDjangoApp(VulnerableApp):
    """Django application runner."""
    
    async def start(self) -> bool:
        """Start Django application."""
        try:
            os.chdir(self.config.app_directory)
            
            # Install dependencies
            subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'], 
                          check=True, capture_output=True)
            
            # Start Django
            self.process = subprocess.Popen(
                [sys.executable, 'app.py'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.config.app_directory
            )
            
            await self._wait_for_startup()
            self.is_running = True
            return True
            
        except Exception as e:
            print(f"Failed to start Django app {self.config.name}: {e}")
            return False
    
    async def stop(self) -> bool:
        """Stop Django application."""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
            
            self.is_running = False
            return True
        return False
    
    async def health_check(self) -> bool:
        """Check Django application health."""
        try:
            response = requests.get(self.config.health_check_url, timeout=5)
            return response.status_code == 200
        except:
            return False
    
    async def _wait_for_startup(self):
        """Wait for Django application to start."""
        for _ in range(self.config.startup_timeout):
            if await self.health_check():
                return
            await asyncio.sleep(1)
        raise TimeoutError(f"Django app {self.config.name} failed to start")


class PHPApp(VulnerableApp):
    """PHP application runner."""
    
    async def start(self) -> bool:
        """Start PHP application."""
        try:
            os.chdir(self.config.app_directory)
            
            # Install composer dependencies if composer.json exists
            if (self.config.app_directory / 'composer.json').exists():
                subprocess.run(['composer', 'install'], check=True, capture_output=True)
            
            # Start PHP built-in server
            self.process = subprocess.Popen([
                'php', '-S', f"{self.config.host}:{self.config.port}", 'app.php'
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.config.app_directory)
            
            await self._wait_for_startup()
            self.is_running = True
            return True
            
        except Exception as e:
            print(f"Failed to start PHP app {self.config.name}: {e}")
            return False
    
    async def stop(self) -> bool:
        """Stop PHP application."""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
            
            self.is_running = False
            return True
        return False
    
    async def health_check(self) -> bool:
        """Check PHP application health."""
        try:
            response = requests.get(self.config.health_check_url, timeout=5)
            return response.status_code == 200
        except:
            return False
    
    async def _wait_for_startup(self):
        """Wait for PHP application to start."""
        for _ in range(self.config.startup_timeout):
            if await self.health_check():
                return
            await asyncio.sleep(1)
        raise TimeoutError(f"PHP app {self.config.name} failed to start")


class JavaSpringApp(VulnerableApp):
    """Java Spring application runner."""
    
    async def start(self) -> bool:
        """Start Java Spring application."""
        try:
            os.chdir(self.config.app_directory)
            
            # Build with Maven
            subprocess.run(['mvn', 'clean', 'compile'], check=True, capture_output=True)
            
            # Start Spring Boot application
            self.process = subprocess.Popen([
                'mvn', 'spring-boot:run', f'-Dspring-boot.run.args=--server.port={self.config.port}'
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.config.app_directory)
            
            await self._wait_for_startup()
            self.is_running = True
            return True
            
        except Exception as e:
            print(f"Failed to start Java app {self.config.name}: {e}")
            return False
    
    async def stop(self) -> bool:
        """Stop Java Spring application."""
        if self.process:
            try:
                # Find and kill Java processes on the port
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    try:
                        if 'java' in proc.info['name'].lower():
                            cmdline = ' '.join(proc.info['cmdline'] or [])
                            if f'server.port={self.config.port}' in cmdline:
                                proc.terminate()
                                proc.wait(timeout=10)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                self.process.terminate()
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
            
            self.is_running = False
            return True
        return False
    
    async def health_check(self) -> bool:
        """Check Java Spring application health."""
        try:
            response = requests.get(self.config.health_check_url, timeout=5)
            return response.status_code == 200
        except:
            return False
    
    async def _wait_for_startup(self):
        """Wait for Java Spring application to start."""
        for _ in range(self.config.startup_timeout * 2):  # Java apps take longer
            if await self.health_check():
                return
            await asyncio.sleep(2)
        raise TimeoutError(f"Java app {self.config.name} failed to start")


class VulnerableAppManager:
    """Manager for all vulnerable applications."""
    
    def __init__(self, apps_directory: Path):
        self.apps_directory = apps_directory
        self.apps: Dict[str, VulnerableApp] = {}
        self.configs: Dict[str, AppConfig] = {}
        self._load_app_configs()
    
    def _load_app_configs(self):
        """Load configuration for all vulnerable applications."""
        
        # Python apps
        self._add_python_apps()
        
        # PHP apps
        self._add_php_apps()
        
        # Java apps
        self._add_java_apps()
        
        # Ruby apps (placeholder for ERB)
        # self._add_ruby_apps()
        
        # JavaScript/Node.js apps (placeholder for Handlebars)
        # self._add_nodejs_apps()
    
    def _add_python_apps(self):
        """Add Python application configurations."""
        
        # Jinja2 Flask App
        jinja2_config = AppConfig(
            name='jinja2_flask',
            engine='jinja2',
            language='python',
            framework='flask',
            host='localhost',
            port=5000,
            startup_command=[sys.executable, 'app.py'],
            startup_timeout=10,
            health_check_url='http://localhost:5000/',
            base_url='http://localhost:5000',
            app_directory=self.apps_directory / 'python' / 'jinja2_flask',
            routes_config={},
            test_payloads={}
        )
        self.configs['jinja2_flask'] = jinja2_config
        self.apps['jinja2_flask'] = PythonFlaskApp(jinja2_config)
        
        # Django Templates App
        django_config = AppConfig(
            name='django_templates',
            engine='django',
            language='python',
            framework='django',
            host='localhost',
            port=8000,
            startup_command=[sys.executable, 'app.py'],
            startup_timeout=15,
            health_check_url='http://localhost:8000/',
            base_url='http://localhost:8000',
            app_directory=self.apps_directory / 'python' / 'django_templates',
            routes_config={},
            test_payloads={}
        )
        self.configs['django_templates'] = django_config
        self.apps['django_templates'] = PythonDjangoApp(django_config)
    
    def _add_php_apps(self):
        """Add PHP application configurations."""
        
        # Twig Symfony App
        twig_config = AppConfig(
            name='twig_symfony',
            engine='twig',
            language='php',
            framework='symfony',
            host='localhost',
            port=8080,
            startup_command=['php', '-S', 'localhost:8080', 'app.php'],
            startup_timeout=10,
            health_check_url='http://localhost:8080/',
            base_url='http://localhost:8080',
            app_directory=self.apps_directory / 'php' / 'twig_symfony',
            routes_config={},
            test_payloads={}
        )
        self.configs['twig_symfony'] = twig_config
        self.apps['twig_symfony'] = PHPApp(twig_config)
        
        # Smarty App
        smarty_config = AppConfig(
            name='smarty',
            engine='smarty',
            language='php',
            framework='smarty',
            host='localhost',
            port=8081,
            startup_command=['php', '-S', 'localhost:8081', 'app.php'],
            startup_timeout=10,
            health_check_url='http://localhost:8081/',
            base_url='http://localhost:8081',
            app_directory=self.apps_directory / 'php' / 'smarty',
            routes_config={},
            test_payloads={}
        )
        self.configs['smarty'] = smarty_config
        self.apps['smarty'] = PHPApp(smarty_config)
    
    def _add_java_apps(self):
        """Add Java application configurations."""
        
        # FreeMarker Spring App
        freemarker_config = AppConfig(
            name='freemarker_spring',
            engine='freemarker',
            language='java',
            framework='spring',
            host='localhost',
            port=8082,
            startup_command=['mvn', 'spring-boot:run'],
            startup_timeout=30,
            health_check_url='http://localhost:8082/',
            base_url='http://localhost:8082',
            app_directory=self.apps_directory / 'java' / 'freemarker_spring',
            routes_config={},
            test_payloads={}
        )
        self.configs['freemarker_spring'] = freemarker_config
        self.apps['freemarker_spring'] = JavaSpringApp(freemarker_config)
    
    async def start_app(self, app_name: str) -> bool:
        """Start a specific application."""
        if app_name not in self.apps:
            print(f"Application {app_name} not found")
            return False
        
        print(f"Starting {app_name}...")
        success = await self.apps[app_name].start()
        
        if success:
            print(f"✅ {app_name} started successfully on {self.configs[app_name].base_url}")
        else:
            print(f"❌ Failed to start {app_name}")
        
        return success
    
    async def stop_app(self, app_name: str) -> bool:
        """Stop a specific application."""
        if app_name not in self.apps:
            print(f"Application {app_name} not found")
            return False
        
        print(f"Stopping {app_name}...")
        success = await self.apps[app_name].stop()
        
        if success:
            print(f"✅ {app_name} stopped successfully")
        else:
            print(f"❌ Failed to stop {app_name}")
        
        return success
    
    async def start_all(self) -> Dict[str, bool]:
        """Start all applications."""
        results = {}
        
        for app_name in self.apps:
            results[app_name] = await self.start_app(app_name)
            await asyncio.sleep(2)  # Delay between starts
        
        return results
    
    async def stop_all(self) -> Dict[str, bool]:
        """Stop all applications."""
        results = {}
        
        for app_name in self.apps:
            results[app_name] = await self.stop_app(app_name)
        
        return results
    
    async def health_check_all(self) -> Dict[str, bool]:
        """Health check all applications."""
        results = {}
        
        for app_name, app in self.apps.items():
            results[app_name] = await app.health_check()
        
        return results
    
    def get_app_info(self, app_name: str) -> Dict[str, Any]:
        """Get information about an application."""
        if app_name not in self.configs:
            return {}
        
        config = self.configs[app_name]
        app = self.apps[app_name]
        
        return {
            'name': config.name,
            'engine': config.engine,
            'language': config.language,
            'framework': config.framework,
            'base_url': config.base_url,
            'is_running': app.is_running,
            'directory': str(config.app_directory)
        }
    
    def list_apps(self) -> List[Dict[str, Any]]:
        """List all available applications."""
        return [self.get_app_info(name) for name in self.apps.keys()]
