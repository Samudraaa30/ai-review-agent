"""
Risk Engine
Determines severity based on detected security evidence.
"""


def calculate_severity(
    source_count,
    validation_count,
    sink_count
):
    """
    Determine vulnerability severity.

    Rules:
    - Critical: Dangerous sink with no validation.
    - High: Dangerous sink exists but some validation present.
    - Medium: Sources without dangerous sinks.
    - Low: Informational finding.
    """

    # Dangerous sink and no validation
    if sink_count > 0 and validation_count == 0:
        return "CRITICAL"

    # Dangerous sink but partially validated
    elif sink_count > 0:
        return "HIGH"

    # Input sources detected but no exploitable sink
    elif source_count > 0:
        return "MEDIUM"

    # Only validations or informational observations
    return "LOW"