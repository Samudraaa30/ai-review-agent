import json

def generate_report(
    findings,
    output_file="report.json"
):

    report = {
        "total_findings": len(findings),
        "findings": findings
    }

    with open(
        output_file,
        "w"
    ) as f:

        json.dump(
            report,
            f,
            indent=4
        )

    return output_file