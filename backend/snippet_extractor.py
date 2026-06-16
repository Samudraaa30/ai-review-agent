from pathlib import Path

def extract_snippet(
    file_path,
    line_number,
    context=10
):

    try:

        lines = Path(
            file_path
        ).read_text(
            encoding="utf-8",
            errors="ignore"
        ).splitlines()

        start = max(
            0,
            line_number - context - 1
        )

        end = min(
            len(lines),
            line_number + context
        )

        return "\n".join(
            lines[start:end]
        )

    except Exception:

        return ""