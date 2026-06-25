"""
Utility module for ReBIT AI SSDLC Review Platform

Provides common utilities including logging and helper functions.
"""
from backend.utils.logger import setup_logger, get_logger, app_logger, log_function_call
from backend.utils.helpers import (
    compute_hash,
    ensure_directory,
    load_json_file,
    save_json_file,
    get_timestamp,
    parse_timestamp,
    is_supported_file,
    discover_files,
    truncate_string,
    sanitize_filename,
    batch_items,
    merge_dicts,
    format_severity,
    validate_severity,
)

__all__ = [
    # Logger
    "setup_logger",
    "get_logger",
    "app_logger",
    "log_function_call",
    
    # Helpers
    "compute_hash",
    "ensure_directory",
    "load_json_file",
    "save_json_file",
    "get_timestamp",
    "parse_timestamp",
    "is_supported_file",
    "discover_files",
    "truncate_string",
    "sanitize_filename",
    "batch_items",
    "merge_dicts",
    "format_severity",
    "validate_severity",
]
