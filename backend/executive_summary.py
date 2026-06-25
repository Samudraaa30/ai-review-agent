import json
import os

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

client = OpenAI(
    api_key=os.getenv("OPENROUTER_API_KEY"),
    base_url="https://openrouter.ai/api/v1",
)

MODEL = os.getenv("OPENROUTER_MODEL", "qwen/qwen3-coder:free")


def generate_summary(findings):

    prompt = f"""
You are a senior ReBIT cybersecurity auditor.

Generate an executive summary for senior management based on the following findings.

Findings:
{json.dumps(findings, indent=2)}

Return a concise report with:

1. Overall Security Posture
2. Critical Risks
3. Business Impact
4. Priority Recommendations

Keep it under 200 words.
"""

    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {
                    "role": "system",
                    "content": "You are a senior cybersecurity auditor."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.2,
            max_tokens=400,
        )

        return response.choices[0].message.content.strip()

    except Exception as e:
        return f"Summary Generation Failed: {e}"