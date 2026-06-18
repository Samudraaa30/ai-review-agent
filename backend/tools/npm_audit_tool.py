import subprocess
import json
from pathlib import Path

def run_npm_audit(
    repo_path
):

    package_file = Path(
        repo_path
    ) / "package.json"

    if not package_file.exists():

        return {}

    try:

        result = subprocess.run(
            [
                "npm",
                "audit",
                "--json"
            ],
            cwd=repo_path,
            capture_output=True,
            text=True
        )

        return json.loads(
            result.stdout
        )

    except Exception as e:

        return {
            "error": str(e)
        }