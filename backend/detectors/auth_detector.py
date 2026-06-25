"""
Authentication Detector Module

Detects authentication-related patterns in code.
"""
from pathlib import Path
from typing import List, Dict, Any

from backend.config import SUPPORTED_EXTENSIONS
from backend.utils.logger import get_logger

logger = get_logger(__name__)

# Known authentication patterns
AUTH_PATTERNS = [
    "JWT",
    "Bearer",
    "Authentication",
    "Authorization",
    "Password",
    "PasswordEncoder",
    "BCrypt",
    "UserDetails",
    "UserDetailsService",
    "SecurityContext",
    "Principal",
    "Login",
    "login",
    "Session",
    "session",
    "Token",
    "token",
    "@PreAuthorize",
    "@RolesAllowed",
    "hasRole(",
    "hasAuthority(",
    "authorizeRequests(",
    "AuthenticationManager"
]


def detect_auth(repo_path: str) -> List[Dict[str, Any]]:
    """
    Detect authentication patterns in repository.

    Args:
        repo_path: Path to repository

    Returns:
        List of detected auth patterns with file, line, and code context
    """
    logger.info(f"Detecting authentication patterns in {repo_path}")

    findings = []
    repo_path = Path(repo_path)

    for file in repo_path.rglob("*"):
        if file.suffix not in SUPPORTED_EXTENSIONS:
            continue

        try:
            lines = file.read_text(encoding="utf-8", errors="ignore").splitlines()

            for line_num, line in enumerate(lines, start=1):
                for pattern in AUTH_PATTERNS:
                    if pattern in line:
                        findings.append({
                            "file": str(file),
                            "line": line_num,
                            "type": pattern,
                            "code": line.strip()
                        })
                        break  # Only report once per line
        except Exception as e:
            logger.warning(f"Error reading {file}: {e}")

    logger.info(f"Found {len(findings)} authentication patterns")
    return findings
