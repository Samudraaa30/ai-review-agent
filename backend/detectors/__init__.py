"""
Detectors module for ReBIT AI SSDLC Review Platform

Provides security pattern detection utilities for various vulnerability types.
"""

from backend.detectors.source_detector import detect_sources
from backend.detectors.sink_detector import detect_sinks
from backend.detectors.validation_detector import detect_validations
from backend.detectors.auth_detector import detect_auth
from backend.detectors.authorization_detector import detect_authorization
from backend.detectors.secret_detector import detect_secrets
from backend.detectors.logging_detector import detect_logging
from backend.detectors.whitelist_detector import detect_whitelisting
from backend.detectors.dependency_detector import detect_dependencies

__all__ = [
    "detect_sources",
    "detect_sinks",
    "detect_validations",
    "detect_auth",
    "detect_authorization",
    "detect_secrets",
    "detect_logging",
    "detect_whitelisting",
    "detect_dependencies",
]
