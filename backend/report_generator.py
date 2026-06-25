"""
Report Generator Module

Provides JSON report generation functionality.
"""
import json
from pathlib import Path
from typing import List, Dict, Any

from backend.config import REPORTS_DIR
from backend.utils.logger import get_logger
from backend.utils.helpers import ensure_directory, get_timestamp

logger = get_logger(__name__)


def generate_report(
    findings: List[Dict[str, Any]],
    output_file: str = None,
    metadata: Dict[str, Any] = None
) -> str:
    """
    Generate a JSON report from findings.
    
    Args:
        findings: List of security findings
        output_file: Optional output file path
        metadata: Optional metadata to include in report
    
    Returns:
        Path to generated report
    """
    if output_file is None:
        timestamp = get_timestamp().replace(":", "-")
        output_file = REPORTS_DIR / f"report_{timestamp}.json"
    else:
        output_file = Path(output_file)
    
    ensure_directory(output_file.parent)
    
    report = {
        "generated_at": get_timestamp(),
        "total_findings": len(findings),
        "metadata": metadata or {},
        "findings": findings
    }
    
    logger.info(f"Generating report with {len(findings)} findings to {output_file}")
    
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4, default=str)
        
        logger.info(f"Report generated successfully: {output_file}")
        return str(output_file)
    except Exception as e:
        logger.error(f"Failed to generate report: {e}")
        raise