from backend.snippet_extractor import (
    extract_snippet
)
from backend.risk_engine import (
    calculate_severity
)

def generate_findings(
    sources,
    validations,
    sinks
):

    findings = []

    for source in sources:

        severity = calculate_severity(
            len(sources),
            len(validations),
            len(sinks)
        )

        snippet = extract_snippet(
            source["file"],
            source["line"]
        )

        findings.append(
            {
                "file": source["file"],
                "line": source["line"],
                "source": source["source"],
                "severity": severity,
                "status": "OPEN",
                "issue":
                    "User-controlled input detected.",
                "recommendation":
                    "Verify validation and sink protection.",
                "snippet":
                    snippet
            }
        )

    return findings