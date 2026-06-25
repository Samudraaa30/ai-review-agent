from backend.qwen_agent import QwenAgent


def review_chunk(chunk: str) -> str:
    """
    AI review of a code chunk using Qwen.
    """

    prompt = f"""
You are an expert cybersecurity code reviewer.

Review this code.

Return:

1. Security Risks
2. Business Impact
3. Technical Impact
4. OWASP Top 10
5. OWASP ASVS
6. Recommendations

Code:

{chunk}
"""

    return QwenAgent.generate(prompt)