def review_finding(finding):

    issue = finding.get(
        "issue",
        "Unknown Issue"
    )

    severity = finding.get(
        "severity",
        "MEDIUM"
    )

    return {
        "risk":
            f"{issue} may expose the application to security risks.",

        "impact":
            "Potential exploitation by attackers if not mitigated.",

        "remediation":
            "Review the code path and apply secure coding controls.",

        "severity":
            severity
    }