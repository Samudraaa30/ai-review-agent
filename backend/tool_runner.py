"""
Tool Runner Module

Provides unified interface for running security tools.
"""
from typing import List, Dict, Any

from backend.tool_registry import TOOLS
from backend.utils.logger import get_logger

logger = get_logger(__name__)


def run_tool(
    review_type: str,
    repo_path: str
) -> List[Dict[str, Any]]:
    """
    Run a security tool for a specific review type.
    
    Args:
        review_type: Type of security review
        repo_path: Path to repository
    
    Returns:
        List of findings from the tool
    """
    logger.info(f"Running tool for {review_type} on {repo_path}")
    
    tool = TOOLS.get(review_type)
    
    if not tool:
        logger.warning(f"No tool registered for review type: {review_type}")
        return []
    
    try:
        findings = tool.execute(repo_path)
        logger.info(f"Tool {review_type} found {len(findings)} findings")
        return findings
    except Exception as e:
        logger.error(f"Tool {review_type} failed: {e}")
        return []