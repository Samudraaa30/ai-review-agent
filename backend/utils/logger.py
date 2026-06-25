"""
Logging utilities for ReBIT AI SSDLC Review Platform

Provides centralized logging with proper formatting, levels, and file handling.
"""
import logging
from pathlib import Path
from datetime import datetime

from backend.config import LOG_LEVEL, LOG_FORMAT, LOG_FILE


def setup_logger(name: str, log_file: Path = None, level: str = None) -> logging.Logger:
    """
    Set up a logger with console and optional file handlers.
    
    Args:
        name: Logger name (typically __name__)
        log_file: Optional log file path
        level: Log level (defaults to config.LOG_LEVEL)
    
    Returns:
        Configured logger instance
    """
    if level is None:
        level = LOG_LEVEL
    
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    
    # Avoid adding duplicate handlers
    if logger.handlers:
        return logger
    
    # Create formatter
    formatter = logging.Formatter(LOG_FORMAT)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, level.upper(), logging.INFO))
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler (optional)
    if log_file is None:
        log_file = LOG_FILE
    
    if log_file:
        try:
            # Ensure log directory exists
            log_file.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(getattr(logging, level.upper(), logging.INFO))
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.warning(f"Could not create file handler: {e}")
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get or create a logger with the given name.
    
    Args:
        name: Logger name
    
    Returns:
        Logger instance
    """
    return setup_logger(name)


# Default application logger
app_logger = setup_logger("rebit_platform")


def log_function_call(logger: logging.Logger = None):
    """
    Decorator to log function calls with arguments and execution time.
    
    Usage:
        @log_function_call
        def my_function(arg1, arg2):
            pass
    """
    import functools
    import time
    
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            nonlocal logger
            if logger is None:
                logger = app_logger
            
            func_name = func.__name__
            logger.debug(f"Calling {func_name} with args={args}, kwargs={kwargs}")
            
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                elapsed = time.time() - start_time
                logger.debug(f"{func_name} completed in {elapsed:.4f}s")
                return result
            except Exception as e:
                elapsed = time.time() - start_time
                logger.error(f"{func_name} failed after {elapsed:.4f}s: {e}")
                raise
        
        return wrapper
    
    return decorator
