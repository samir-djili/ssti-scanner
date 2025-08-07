"""
Factory for creating template engine instances.

This module provides a centralized way to create and manage
template engine detection plugins.
"""

from typing import Dict, List, Optional, Type

from .base import BaseTemplateEngine
from .jinja2_engine import Jinja2Engine
from .twig_engine import TwigEngine
from .freemarker_engine import FreemarkerEngine
from .velocity_engine import VelocityEngine
from .smarty_engine import SmartyEngine
from .thymeleaf_engine import ThymeleafEngine
from .handlebars_engine import HandlebarsEngine
from .django_engine import DjangoEngine
from .erb_engine import ERBEngine


class EngineFactory:
    """Factory for creating template engine instances."""
    
    _engines: Dict[str, Type[BaseTemplateEngine]] = {
        'jinja2': Jinja2Engine,
        'twig': TwigEngine,
        'freemarker': FreemarkerEngine,
        'velocity': VelocityEngine,
        'smarty': SmartyEngine,
        'thymeleaf': ThymeleafEngine,
        'handlebars': HandlebarsEngine,
        'django': DjangoEngine,
        'erb': ERBEngine,
    }
    
    @classmethod
    def get_available_engines(cls) -> List[str]:
        """Get list of available engine names."""
        return list(cls._engines.keys())
    
    @classmethod
    def create_engine(cls, engine_name: str, config=None) -> Optional[BaseTemplateEngine]:
        """
        Create a template engine instance by name.
        
        Args:
            engine_name: Name of the engine to create
            config: Configuration object for the engine
            
        Returns:
            BaseTemplateEngine instance or None if not found
        """
        engine_class = cls._engines.get(engine_name.lower())
        if engine_class:
            return engine_class(config or {})
        return None
    
    @classmethod
    def create_all_engines(cls, config=None) -> List[BaseTemplateEngine]:
        """Create instances of all available engines."""
        engines = []
        for engine_class in cls._engines.values():
            engines.append(engine_class(config or {}))
        return engines
    
    @classmethod
    def create_engines(cls, engine_names: List[str]) -> List[TemplateEngine]:
        """
        Create instances of specified engines.
        
        Args:
            engine_names: List of engine names to create
            
        Returns:
            List of TemplateEngine instances
        """
        engines = []
        for name in engine_names:
            engine = cls.create_engine(name)
            if engine:
                engines.append(engine)
        return engines
    
    @classmethod
    def register_engine(cls, name: str, engine_class: Type[TemplateEngine]) -> None:
        """
        Register a new template engine.
        
        Args:
            name: Name of the engine
            engine_class: TemplateEngine class
        """
        cls._engines[name.lower()] = engine_class
    
    @classmethod
    def is_engine_available(cls, engine_name: str) -> bool:
        """Check if an engine is available."""
        return engine_name.lower() in cls._engines
