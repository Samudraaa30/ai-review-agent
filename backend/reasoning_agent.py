"""
Reasoning Agent Module

Provides rule-based file selection for security reviews.
"""
from pathlib import Path
from typing import List, Dict

from backend.utils.logger import get_logger

logger = get_logger(__name__)

# Review type keywords mapping
REVIEW_KEYWORDS = {
    "Input Validation": [
        "controller",
        "request",
        "input",
        "route",
        "api",
        "param",
        "body",
        "query"
    ],
    "Authentication Review": [
        "auth",
        "login",
        "jwt",
        "security",
        "user",
        "session",
        "token",
        "password"
    ],
    "Authorization Review": [
        "role",
        "permission",
        "access",
        "authorize",
        "admin",
        "privilege"
    ],
    "Secrets Detection": [
        "secret",
        "token",
        "key",
        "password",
        "credential",
        "api_key",
        "private"
    ]
}


def select_relevant_files(
    repo_path: str,
    review_type: str,
    max_files: int = 20
) -> List[str]:
    """
    Select relevant files for a specific review type using keyword matching.
    
    Args:
        repo_path: Repository root path
        review_type: Type of security review
        max_files: Maximum number of files to return
    
    Returns:
        List of relevant file paths
    """
    logger.info(f"Selecting files for {review_type} review")
    
    keywords = REVIEW_KEYWORDS.get(review_type, [])
    
    if not keywords:
        logger.warning(f"No keywords defined for review type: {review_type}")
        return []
    
    relevant_files = []
    repo_path = Path(repo_path)
    
    for file in repo_path.rglob("*"):
        if not file.is_file():
            continue
        
        file_name = file.name.lower()
        
        for keyword in keywords:
            if keyword in file_name:
                relevant_files.append(str(file))
                break
    
    logger.info(f"Found {len(relevant_files)} relevant files for {review_type}")
    return relevant_files[:max_files]