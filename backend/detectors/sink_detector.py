"""
Sink Detector Module

Detects dangerous sink operations in code.
"""
from pathlib import Path
from typing import List, Dict, Any

from backend.config import SUPPORTED_EXTENSIONS
from backend.utils.logger import get_logger

logger = get_logger(__name__)

# Known dangerous sink patterns
SINKS = [
    "executeQuery(",
    "executeUpdate(",
    "Statement.execute(",
    "Runtime.getRuntime().exec(",
    "ProcessBuilder(",
    "eval(",
    "innerHTML",
    "document.write("
]


def detect_sinks(repo_path: str) -> List[Dict[str, Any]]:
    """
    Detect dangerous sink operations in repository.

    Args:
        repo_path: Path to repository

    Returns:
        List of detected sinks with file, line, and code context
    """
    logger.info(f"Detecting sinks in {repo_path}")

    findings = []
    repo_path = Path(repo_path)

    for file in repo_path.rglob("*"):
        if file.suffix not in SUPPORTED_EXTENSIONS:
            continue

        try:
            lines = file.read_text(encoding="utf-8", errors="ignore").splitlines()

            for line_num, line in enumerate(lines, start=1):
                for sink in SINKS:
                    if sink in line:
                        findings.append({
                            "file": str(file),
                            "line": line_num,
                            "sink": sink,
                            "code": line.strip()
                        })
                        break  # Only report once per line
        except Exception as e:
            logger.warning(f"Error reading {file}: {e}")

    logger.info(f"Found {len(findings)} sinks")
    return findings
