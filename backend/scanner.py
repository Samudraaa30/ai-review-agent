"""
Repository Scanner Module

Provides file discovery and repository scanning utilities.
"""
from pathlib import Path
from typing import List

from backend.config import SUPPORTED_EXTENSIONS
from backend.utils.logger import get_logger

logger = get_logger(__name__)


def discover_files(repo_path: str, extensions: List[str] = None) -> List[str]:
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
    
    logger.debug(f"Scanning repository: {repo_path}")
    
    for file in repo_path.rglob("*"):
        if file.is_file() and file.suffix in extensions:
            files.append(str(file))
    
    logger.info(f"Discovered {len(files)} files")
    return sorted(files)