"""
Source Detector Module

Detects user-controlled input sources in code.
"""
from pathlib import Path
from typing import List, Dict, Any

from backend.config import SUPPORTED_EXTENSIONS
from backend.utils.logger import get_logger

logger = get_logger(__name__)

# Known input source patterns by language
SOURCES = [
    "req.body",
    "req.query",
    "req.params",
    "@RequestBody",
    "request.getParameter",
    "input("
]


def detect_sources(repo_path: str) -> List[Dict[str, Any]]:
    """
    Detect user-controlled input sources in repository.

    Args:
        repo_path: Path to repository

    Returns:
        List of detected sources with file, line, and code context
    """
    logger.info(f"Detecting sources in {repo_path}")

    findings = []
    repo_path = Path(repo_path)

    for file in repo_path.rglob("*"):
        if file.suffix not in SUPPORTED_EXTENSIONS:
            continue

        try:
            lines = file.read_text(encoding="utf-8", errors="ignore").splitlines()

            for line_num, line in enumerate(lines, start=1):
                for source in SOURCES:
                    if source in line:
                        findings.append({
                            "file": str(file),
                            "line": line_num,
                            "source": source,
                            "code": line.strip()
                        })
                        break  # Only report once per line
        except Exception as e:
            logger.warning(f"Error reading {file}: {e}")

    logger.info(f"Found {len(findings)} sources")
    return findings
