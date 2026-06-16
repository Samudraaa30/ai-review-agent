def generate_auth_findings(
    auth_matches
):

    findings = []

    for match in auth_matches:

        findings.append(
            {
                "severity": "INFO",
                "status": "REVIEW",
                "file": match["file"],
                "line": match["line"],
                "issue":
                    f"Authentication pattern detected: {match['type']}",
                "recommendation":
                    "Verify authentication and authorization controls.",
                "code":
                    match["code"]
            }
        )

    return findings