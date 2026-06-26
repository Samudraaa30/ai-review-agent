import json
import os
from dataclasses import asdict, is_dataclass


def generate_report(
    session_id,
    repository,
    findings,
    risk_score,
    summary,
):
    os.makedirs("reports", exist_ok=True)

    output_file = f"reports/{session_id}.json"

    report = {
        "session_id": session_id,
        "repository": repository,
        "risk_score": risk_score,
        "summary": summary,
        "total_findings": len(findings),
        "findings": [
            asdict(f) if is_dataclass(f) else f
            for f in findings
        ],
    }

    with open(output_file, "w") as f:
        json.dump(report, f, indent=4)

    return output_file