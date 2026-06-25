"""
Security Tool Base Class

Abstract base class for all security tools.
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any

from backend.utils.logger import get_logger

logger = get_logger(__name__)


class SecurityTool(ABC):
    """Base class for security scanning tools."""
    
    name = "BaseTool"
    
    @abstractmethod
    def execute(self, repo_path: str) -> List[Dict[str, Any]]:
        """
        Execute the security tool on a repository.
        
        Args:
            repo_path: Path to the repository
        
        Returns:
            List of security findings
        """
        raise NotImplementedError("Subclasses must implement execute method")