from pathlib import Path

VALIDATION_PATTERNS = [
    "@Valid",
    "validator",
    "sanitize",
    "Joi",
    "zod",
    "Pattern",
    "matches(",
    "isValid"
]

def detect_validations(repo_path):

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

                for validation in VALIDATION_PATTERNS:

                    if validation in line:

                        findings.append(
                            {
                                "file": str(file),
                                "line": line_num,
                                "validation": validation,
                                "code": line.strip()
                            }
                        )

        except Exception:
            pass

    return findings