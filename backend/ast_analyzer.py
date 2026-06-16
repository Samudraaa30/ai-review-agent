from pathlib import Path
import ast

def analyze_python_ast(repo_path):

    results = {
        "functions": [],
        "classes": []
    }

    for file in Path(repo_path).rglob("*.py"):

        try:

            tree = ast.parse(
                file.read_text(
                    encoding="utf-8",
                    errors="ignore"
                )
            )

            for node in ast.walk(tree):

                if isinstance(
                    node,
                    ast.FunctionDef
                ):

                    results[
                        "functions"
                    ].append(
                        node.name
                    )

                elif isinstance(
                    node,
                    ast.ClassDef
                ):

                    results[
                        "classes"
                    ].append(
                        node.name
                    )

        except Exception:
            pass

    return results