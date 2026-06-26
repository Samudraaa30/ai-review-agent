"""
Risk Score Calculator
Calculates an overall repository risk score (0-100).
"""


def calculate_risk_score(findings):

    if not findings:
        return 0

    weights = {
        "CRITICAL": 10,
        "HIGH": 7,
        "MEDIUM": 4,
        "LOW": 1
    }

    total = 0

    for finding in findings:
        severity = finding.get("severity", "LOW").upper()
        total += weights.get(severity, 1)

    # Average severity (1–10)
    avg = total / len(findings)

    # Scale to 0–100
    score = round(avg * 10)

    return min(score, 100)