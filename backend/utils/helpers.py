"""
Utility functions for ReBIT AI SSDLC Review Platform

Common helper functions used across the application.
"""
import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from backend.config import SUPPORTED_EXTENSIONS


def compute_hash(data: Any) -> str:
    """
    Compute SHA-256 hash of data.
    
    Args:
        data: Data to hash (will be JSON serialized if not string)
    
    Returns:
        Hex digest string
    """
    if isinstance(data, str):
        data_str = data
    else:
        data_str = json.dumps(data, sort_keys=True)
    
    return hashlib.sha256(data_str.encode()).hexdigest()


def ensure_directory(path: Path) -> Path:
    """
    Ensure a directory exists, creating it if necessary.
    
    Args:
        path: Directory path
    
    Returns:
        The same path (for chaining)
    """
    path.mkdir(parents=True, exist_ok=True)
    return path


def load_json_file(file_path: Path, default: Any = None) -> Any:
    """
    Load JSON from file with error handling.
    
    Args:
        file_path: Path to JSON file
        default: Default value if file doesn't exist
    
    Returns:
        Parsed JSON data or default value
    """
    if not file_path.exists():
        return default
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        raise ValueError(f"Failed to load JSON from {file_path}: {e}")


def save_json_file(file_path: Path, data: Any, indent: int = 2) -> None:
    """
    Save data to JSON file with error handling.
    
    Args:
        file_path: Path to JSON file
        data: Data to save
        indent: JSON indentation level
    """
    try:
        ensure_directory(file_path.parent)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent, default=str)
    except IOError as e:
        raise ValueError(f"Failed to save JSON to {file_path}: {e}")


def get_timestamp() -> str:
    """
    Get current UTC timestamp in ISO format.
    
    Returns:
        ISO format timestamp string
    """
    return datetime.now(timezone.utc).isoformat()


def parse_timestamp(timestamp_str: str) -> datetime:
    """
    Parse ISO format timestamp string to datetime.
    
    Args:
        timestamp_str: ISO format timestamp
    
    Returns:
        datetime object
    """
    return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))


def is_supported_file(file_path: Path) -> bool:
    """
    Check if a file has a supported extension.
    
    Args:
        file_path: Path to check
    
    Returns:
        True if file extension is supported
    """
    return file_path.suffix in SUPPORTED_EXTENSIONS


def discover_files(repo_path: Path, extensions: List[str] = None) -> List[str]:
    """
    Discover all supported files in a repository.
    
    Args:
        repo_path: Repository root path
        extensions: Optional list of extensions to search for
    
    Returns:
        List of file paths
    """
    if extensions is None:
        extensions = SUPPORTED_EXTENSIONS
    
    files = []
    repo_path = Path(repo_path)
    
    for file in repo_path.rglob("*"):
        if file.is_file() and file.suffix in extensions:
            files.append(str(file))
    
    return sorted(files)


def truncate_string(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """
    Truncate a string to maximum length.
    
    Args:
        text: Text to truncate
        max_length: Maximum length
        suffix: Suffix to add if truncated
    
    Returns:
        Truncated string
    """
    if len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename by removing invalid characters.
    
    Args:
        filename: Original filename
    
    Returns:
        Sanitized filename
    """
    # Remove or replace invalid characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, "_")
    
    return filename.strip()


def batch_items(items: List[Any], batch_size: int) -> List[List[Any]]:
    """
    Split a list into batches.
    
    Args:
        items: List to split
        batch_size: Size of each batch
    
    Returns:
        List of batches
    """
    return [items[i:i + batch_size] for i in range(0, len(items), batch_size)]


def merge_dicts(dict1: Dict, dict2: Dict, overwrite: bool = True) -> Dict:
    """
    Merge two dictionaries.
    
    Args:
        dict1: Base dictionary
        dict2: Dictionary to merge in
        overwrite: If True, dict2 values overwrite dict1 values
    
    Returns:
        Merged dictionary
    """
    result = dict1.copy()
    
    for key, value in dict2.items():
        if key not in result or overwrite:
            result[key] = value
    
    return result


def format_severity(severity: str) -> str:
    """
    Format severity string to standard case.
    
    Args:
        severity: Severity string
    
    Returns:
        Formatted severity (uppercase)
    """
    return severity.upper() if severity else "UNKNOWN"


def validate_severity(severity: str) -> bool:
    """
    Validate severity value.
    
    Args:
        severity: Severity to validate
    
    Returns:
        True if valid severity
    """
    valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    return severity.upper() in valid_severities if severity else False
