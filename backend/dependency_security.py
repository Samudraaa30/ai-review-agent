from backend.tools.npm_audit_tool import (
    run_npm_audit
)

def dependency_security_review(
    repo_path
):

    data = run_npm_audit(
        repo_path
    )

    findings = []

    vulnerabilities = data.get(
        "vulnerabilities",
        {}
    )

    for package, info in vulnerabilities.items():

        findings.append(
            {
                "package": package,
                "severity": info.get(
                    "severity",
                    "unknown"
                )
            }
        )

    return findings