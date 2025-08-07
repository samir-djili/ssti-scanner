"""
Logging utilities for SSTI Scanner.

This module provides centralized logging configuration with:
- Colored console output
- Structured logging
- Debug and verbose modes
- Performance logging
"""

import logging
import sys
from typing import Optional

from colorama import Fore, Back, Style, init

# Initialize colorama for Windows support
init(autoreset=True)


class ColoredFormatter(logging.Formatter):
    """Custom formatter with color support."""
    
    # Color mapping for different log levels
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Back.WHITE + Style.BRIGHT,
    }
    
    def __init__(self, colored: bool = True):
        """Initialize colored formatter."""
        self.colored = colored
        super().__init__()
    
    def format(self, record):
        """Format log record with colors."""
        # Create base format
        if self.colored:
            level_color = self.COLORS.get(record.levelname, '')
            reset = Style.RESET_ALL
            
            # Format: [TIMESTAMP] LEVEL - MODULE: MESSAGE
            log_format = f"[{Fore.BLUE}%(asctime)s{reset}] {level_color}%(levelname)s{reset} - {Fore.MAGENTA}%(name)s{reset}: %(message)s"
        else:
            log_format = "[%(asctime)s] %(levelname)s - %(name)s: %(message)s"
        
        formatter = logging.Formatter(
            log_format,
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        return formatter.format(record)


class SSTILogger:
    """Centralized logger for SSTI Scanner."""
    
    _loggers = {}
    _configured = False
    
    @classmethod
    def configure(cls, debug: bool = False, verbose: bool = False, 
                 colored: bool = True, log_file: Optional[str] = None):
        """Configure global logging settings."""
        if cls._configured:
            return
        
        # Determine log level
        if debug:
            level = logging.DEBUG
        elif verbose:
            level = logging.INFO
        else:
            level = logging.WARNING
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(level)
        
        # Clear existing handlers
        root_logger.handlers.clear()
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(ColoredFormatter(colored))
        root_logger.addHandler(console_handler)
        
        # File handler (if specified)
        if log_file:
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)  # Always debug level for files
            file_handler.setFormatter(ColoredFormatter(colored=False))
            root_logger.addHandler(file_handler)
        
        # Suppress noisy third-party loggers
        logging.getLogger('aiohttp').setLevel(logging.WARNING)
        logging.getLogger('asyncio').setLevel(logging.WARNING)
        logging.getLogger('urllib3').setLevel(logging.WARNING)
        
        cls._configured = True
    
    @classmethod
    def get_logger(cls, name: str, debug: bool = False) -> logging.Logger:
        """Get logger instance for module."""
        if not cls._configured:
            cls.configure(debug=debug)
        
        if name not in cls._loggers:
            logger = logging.getLogger(name)
            cls._loggers[name] = logger
        
        return cls._loggers[name]


def get_logger(name: str, debug: bool = False) -> logging.Logger:
    """
    Get logger instance for a module.
    
    Args:
        name: Logger name (typically __name__)
        debug: Enable debug logging
        
    Returns:
        Logger instance
    """
    return SSTILogger.get_logger(name, debug)


def configure_logging(debug: bool = False, verbose: bool = False, 
                     colored: bool = True, log_file: Optional[str] = None):
    """
    Configure global logging settings.
    
    Args:
        debug: Enable debug logging
        verbose: Enable verbose logging
        colored: Enable colored output
        log_file: Optional log file path
    """
    SSTILogger.configure(debug, verbose, colored, log_file)
