"""
Risk Engine Module

Provides severity calculation based on security analysis results.
"""
from backend.utils.logger import get_logger

logger = get_logger(__name__)


def calculate_severity(
    source_count: int,
    validation_count: int,
    sink_count: int
) -> str:
    """
    Calculate severity level based on sources, validations, and sinks.
    
    Args:
        source_count: Number of user input sources detected
        validation_count: Number of validation mechanisms detected
        sink_count: Number of dangerous sinks detected
    
    Returns:
        Severity level string (CRITICAL, HIGH, MEDIUM, LOW)
    """
    logger.debug(f"Calculating severity: sources={source_count}, validations={validation_count}, sinks={sink_count}")
    
    # Critical: Sinks without validation
    if sink_count > 0 and validation_count == 0:
        return "CRITICAL"
    
    # High: Sinks present
    if sink_count > 0:
        return "HIGH"
    
    # Medium: Validations present but no sinks
    if validation_count > 0:
        return "MEDIUM"
    
    # Low: Only sources detected
    return "LOW"