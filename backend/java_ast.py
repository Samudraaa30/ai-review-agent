from pathlib import Path
import re

def analyze_java(repo_path):

    classes = []
    methods = []

    class_pattern = re.compile(
        r"\bclass\s+([A-Za-z0-9_]+)"
    )

    method_pattern = re.compile(
        r"(public|private|protected).*?\s+([A-Za-z0-9_]+)\s*\("
    )

    for file in Path(repo_path).rglob("*.java"):

        try:

            content = file.read_text(
                encoding="utf-8",
                errors="ignore"
            )

            for match in class_pattern.finditer(content):

                classes.append(
                    match.group(1)
                )

            for match in method_pattern.finditer(content):

                methods.append(
                    match.group(2)
                )

        except Exception:
            pass

    return {
        "classes": classes,
        "methods": methods
    }