"""
Template engine detection plugins for SSTI Scanner.

This module provides a plugin-based architecture for detecting various
template engines and their specific vulnerabilities.
"""

from .base import BaseTemplateEngine, EngineResult, ConfidenceLevel, Payload
from .jinja2_engine import Jinja2Engine
from .twig_engine import TwigEngine
from .freemarker_engine import FreemarkerEngine
from .velocity_engine import VelocityEngine
from .smarty_engine import SmartyEngine
from .thymeleaf_engine import ThymeleafEngine
from .handlebars_engine import HandlebarsEngine
from .django_engine import DjangoEngine
from .erb_engine import ERBEngine
from .engine_factory import EngineFactory

__all__ = [
    'BaseTemplateEngine',
    'EngineResult',
    'ConfidenceLevel', 
    'Payload',
    'Jinja2Engine',
    'TwigEngine',
    'FreemarkerEngine',
    'VelocityEngine',
    'SmartyEngine',
    'ThymeleafEngine',
    'HandlebarsEngine',
    'DjangoEngine',
    'ERBEngine',
    'EngineFactory'
]
