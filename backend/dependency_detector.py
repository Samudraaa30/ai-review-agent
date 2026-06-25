from pathlib import Path

DEPENDENCY_FILES = [
    "requirements.txt",
    "package.json",
    "pom.xml"
]

def detect_dependencies(
    repo_path
):

    findings = []

    for file in Path(repo_path).rglob("*"):

        if file.name not in DEPENDENCY_FILES:
            continue

        try:

            content = file.read_text(
                encoding="utf-8",
                errors="ignore"
            )

            findings.append(
              {
                "rule": "DEPENDENCY",

                "severity": "LOW",
   
                "issue": "Dependency manifest detected",

                "file": str(file),

                "line": 1,

                "code": content[:1000]
              }
            )

        except Exception:
            pass

    return findings