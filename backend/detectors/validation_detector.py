"""
Validation Detector Module

Detects input validation mechanisms in code.
"""
from pathlib import Path
from typing import List, Dict, Any

from backend.config import SUPPORTED_EXTENSIONS
from backend.utils.logger import get_logger

logger = get_logger(__name__)

# Known validation patterns
VALIDATION_PATTERNS = [
    "@Valid",
    "validator",
    "sanitize",
    "Joi",
    "zod",
    "Pattern",
    "matches(",
    "isValid"
]


def detect_validations(repo_path: str) -> List[Dict[str, Any]]:
    """
    Detect input validation mechanisms in repository.

    Args:
        repo_path: Path to repository

    Returns:
        List of detected validations with file, line, and code context
    """
    logger.info(f"Detecting validations in {repo_path}")

    findings = []
    repo_path = Path(repo_path)

    for file in repo_path.rglob("*"):
        if file.suffix not in SUPPORTED_EXTENSIONS:
            continue

        try:
            lines = file.read_text(encoding="utf-8", errors="ignore").splitlines()

            for line_num, line in enumerate(lines, start=1):
                for pattern in VALIDATION_PATTERNS:
                    if pattern in line:
                        findings.append({
                            "file": str(file),
                            "line": line_num,
                            "validation": pattern,
                            "code": line.strip()
                        })
                        break  # Only report once per line
        except Exception as e:
            logger.warning(f"Error reading {file}: {e}")

    logger.info(f"Found {len(findings)} validations")
    return findings
