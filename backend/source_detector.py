from pathlib import Path

SOURCES = [
    "req.body",
    "req.query",
    "req.params",
    "@RequestBody",
    "request.getParameter",
    "input("
]

def detect_sources(repo_path):

    findings = []

    for file in Path(repo_path).rglob("*"):

        if file.suffix not in [
            ".java",
            ".js",
            ".ts",
            ".py",
            ".php",
            ".html",
            ".css"
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

                for source in SOURCES:

                    if source in line:

                        findings.append(
                            {
                                "file": str(file),
                                "line": line_num,
                                "source": source,
                                "code": line.strip()
                            }
                        )

        except Exception:
            pass

    return findings