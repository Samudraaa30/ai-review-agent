from pathlib import Path

from git import index

def build_repository_index(
    repo_path
):

    index = {
        "files": [],
        "python_files": 0,
        "java_files": 0,
        "js_files": 0,
        "ts_files": 0,
        "php_files": 0,
        "html_files": 0,
        "css_files": 0,
    }

    for file in Path(
        repo_path
    ).rglob("*"):

        if not file.is_file():
            continue

        index["files"].append(
            str(file)
        )

        suffix = file.suffix.lower()

        if suffix == ".py":
            index["python_files"] += 1

        elif suffix == ".java":
            index["java_files"] += 1

        elif suffix == ".js":
            index["js_files"] += 1

        elif suffix == ".ts":
            index["ts_files"] += 1
        elif suffix == ".php":
             index["php_files"] += 1

        elif suffix == ".html":
             index["html_files"] += 1

        elif suffix == ".css":
            index["css_files"] += 1

    return index