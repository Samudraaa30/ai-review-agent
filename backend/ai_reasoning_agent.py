from backend.qwen_agent import QwenAgent


def select_relevant_files_ai(files, review_type):
    """
    Uses Qwen to identify the most security-relevant files.
    """

    return QwenAgent.select_relevant_files(
        files,
        review_type
    )