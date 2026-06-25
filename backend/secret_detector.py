from pathlib import Path
import re

PATTERNS = {
    "AWS Key": r"AKIA[0-9A-Z]{16}",
    "Password": r"password\s*=",
    "API Key": r"apikey\s*=",
    "Token": r"token\s*="
}

def detect_secrets(repo_path):

    findings = []

    for file in Path(repo_path).rglob("*"):

        if file.suffix not in [
            ".py",
            ".js",
            ".ts",
            ".java",
            ".env"
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

                for secret_type, pattern in PATTERNS.items():

                    if re.search(
                        pattern,
                        line,
                        re.IGNORECASE
                    ):

                       findings.append(
                    {
                      "rule": "SECRET",

                      "severity": "HIGH",

                      "issue": f"{secret_type} detected",

                      "file": str(file),

                      "line": line_num,

                      "code": line.strip()
                    }
                )

        except Exception:
            pass

    return findings