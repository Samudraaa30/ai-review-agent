"""
Metrics Module

Provides severity counting and metrics calculation utilities.
"""
from typing import Dict, List, Any

from backend.utils.logger import get_logger

logger = get_logger(__name__)


def severity_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Count findings by severity level.
    
    Args:
        findings: List of finding dictionaries
    
    Returns:
        Dictionary with severity counts
    """
    result = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }
    
    for finding in findings:
        severity = finding.get("severity", "INFO").upper()
        if severity in result:
            result[severity] += 1
        else:
            logger.warning(f"Unknown severity level: {severity}")
            result["INFO"] += 1
    
    logger.debug(f"Severity counts: {result}")
    return result