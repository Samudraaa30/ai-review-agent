"""
Input Validation Security Tool

Scans for input validation vulnerabilities using source/sink analysis.
"""
from typing import List, Dict, Any

from backend.security_tool import SecurityTool
from backend.source_detector import detect_sources
from backend.validation_detector import detect_validations
from backend.sink_detector import detect_sinks
from backend.finding_engine import generate_findings
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class InputValidationTool(SecurityTool):
    """Tool for detecting input validation vulnerabilities."""
    
    name = "Input Validation"
    
    def execute(self, repo_path: str) -> List[Dict[str, Any]]:
        """
        Execute input validation scan.
        
        Args:
            repo_path: Path to repository
        
        Returns:
            List of findings
        """
        logger.info(f"Running input validation scan on {repo_path}")
        
        sources = detect_sources(repo_path)
        validations = detect_validations(repo_path)
        sinks = detect_sinks(repo_path)
        
        logger.info(
            f"Scan results: {len(sources)} sources, "
            f"{len(validations)} validations, "
            f"{len(sinks)} sinks"
        )
        
        findings = generate_findings(sources, validations, sinks)
        
        logger.info(f"Generated {len(findings)} input validation findings")
        return findings