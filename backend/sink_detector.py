from pathlib import Path

SINKS = [
    "executeQuery(",
    "executeUpdate(",
    "Statement.execute(",
    "Runtime.getRuntime().exec(",
    "ProcessBuilder(",
    "eval(",
    "innerHTML",
    "document.write("
]

def detect_sinks(repo_path):

    findings = []

    for file in Path(repo_path).rglob("*"):

        if file.suffix not in [
            ".java",
            ".js",
            ".ts",
            ".py"
        ]:
            continue

        try:

            lines = file.read_text(
                encoding="utf-8",
                errors="ignore"
            ).splitlines()

            for line_num, line in enumerate(
                lines,
                start=1
            ):

                for sink in SINKS:

                    if sink in line:

                        findings.append(
                            {
                                "file": str(file),
                                "line": line_num,
                                "sink": sink,
                                "code": line.strip()
                            }
                        )

        except Exception:
            pass

    return findings