def calculate_severity(
    source_count,
    validation_count,
    sink_count
):

    if sink_count > 0 and validation_count == 0:
        return "CRITICAL"

    if sink_count > 0:
        return "HIGH"

    if validation_count > 0:
        return "MEDIUM"

    return "LOW"