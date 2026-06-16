from pathlib import Path

SUPPORTED_EXTENSIONS = [
    ".java",
    ".js",
    ".ts",
    ".py"
]

def discover_files(repo_path):
    files = []

    for file in Path(repo_path).rglob("*"):
        if file.suffix in SUPPORTED_EXTENSIONS:
            files.append(str(file))

    return files