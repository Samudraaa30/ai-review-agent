def calculate_risk_score(findings):

    if not findings:
        return 0

    total = 0

    for finding in findings:

        severity = finding.get(
            "severity",
            "LOW"
        )

        if severity == "CRITICAL":
            total += 10

        elif severity == "HIGH":
            total += 7

        elif severity == "MEDIUM":
            total += 4

        else:
            total += 1

    score = total / len(findings)

    return round(
        score * 10
    )