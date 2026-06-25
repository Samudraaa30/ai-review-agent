"""
Repository Clone Module

Handles repository cloning operations.
"""
from git import Repo
from pathlib import Path
import uuid

from backend.config import REPOS_DIR
from backend.utils.logger import get_logger

logger = get_logger(__name__)


def clone_repository(repo_url: str) -> str:
    """
    Clone a repository to the local repos directory.
    
    Args:
        repo_url: URL of the repository to clone
    
    Returns:
        Path to the cloned repository
    """
    repo_id = str(uuid.uuid4())
    target_path = REPOS_DIR / repo_id
    
    logger.info(f"Cloning repository {repo_url} to {target_path}")
    
    try:
        Repo.clone_from(repo_url, target_path)
        logger.info(f"Successfully cloned repository to {target_path}")
        return str(target_path)
    except Exception as e:
        logger.error(f"Failed to clone repository: {e}")
        raise