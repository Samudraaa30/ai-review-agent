"""
Finding Engine Module

Generates security findings from source, validation, and sink analysis.
"""
from typing import List, Dict, Any

from backend.snippet_extractor import extract_snippets
from backend.risk_engine import calculate_severity
from backend.utils.logger import get_logger

logger = get_logger(__name__)


def generate_findings(
    sources: List[Dict[str, Any]],
    validations: List[Dict[str, Any]],
    sinks: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Generate security findings from analysis results.
    
    Args:
        sources: List of detected input sources
        validations: List of detected validations
        sinks: List of detected dangerous sinks
    
    Returns:
        List of security findings
    """
    logger.info(f"Generating findings: {len(sources)} sources, {len(validations)} validations, {len(sinks)} sinks")
    
    findings = []
    
    for source in sources:
        severity = calculate_severity(
            len(sources),
            len(validations),
            len(sinks)
        )
        
        snippet = extract_snippets(
            source["file"],
            source["line"]
        )
        
        finding = {
            "file": source["file"],
            "line": source["line"],
            "source": source["source"],
            "severity": severity,
            "status": "OPEN",
            "issue": "User-controlled input detected.",
            "recommendation": "Verify validation and sink protection.",
            "snippet": snippet
        }
        
        findings.append(finding)
    
    logger.info(f"Generated {len(findings)} findings")
    return findings