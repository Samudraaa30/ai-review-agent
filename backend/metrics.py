def severity_counts(findings):

    result = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for finding in findings:

        severity = finding["severity"]

        if severity in result:
            result[severity] += 1

    return result