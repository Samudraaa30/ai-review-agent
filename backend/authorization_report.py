def generate_authorization_findings(
    matches
):

    findings = []

    for match in matches:

        findings.append(
            {
                "severity": "INFO",
                "status": "REVIEW",
                "file": match["file"],
                "line": match["line"],
                "issue":
                    f"Authorization pattern detected: {match['type']}",
                "recommendation":
                    "Verify role-based access controls are correctly implemented.",
                "code":
                    match["code"]
            }
        )

    return findings