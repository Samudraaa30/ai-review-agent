"""
Qwen AI Gateway
Centralized LLM interface for the ReBIT AI SSDLC Review Platform.
"""

import json
import os
import requests
from dotenv import load_dotenv

load_dotenv()

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
MODEL = os.getenv("OPENROUTER_MODEL", "qwen/qwen3-coder:free")


class QwenAgent:

    @staticmethod
    def generate(prompt: str) -> str:
        """
        Send a prompt to OpenRouter.
        """

        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": MODEL,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            },
            timeout=300
        )

        print(response.status_code)
        print(response.text)

        response.raise_for_status()

        return response.json()["choices"][0]["message"]["content"]

    @staticmethod
    def review_finding(finding: dict):

        prompt = f"""
You are an expert cybersecurity reviewer.

Analyze the following security finding.

Finding:

{json.dumps(finding, indent=2)}

Return ONLY valid JSON.

Format:

{{
    "risk":"...",
    "business_impact":"...",
    "technical_impact":"...",
    "owasp":"...",
    "asvs":"...",
    "recommendation":"...",
    "confidence":95
}}

Do not explain.
Only return JSON.
"""

        try:
            result = QwenAgent.generate(prompt)
            return json.loads(result)

        except Exception as e:
            import traceback
            traceback.print_exc()
            return {
                "risk": "AI Review Failed",
                "business_impact": str(e),
                "technical_impact": "",
                "owasp": "",
                "asvs": "",
                "recommendation": "Verify OpenRouter API key and model.",
                "confidence": 0
            }

    @staticmethod
    def select_relevant_files(files, review_type):

        file_text = "\n".join(files)

        prompt = f"""
You are an expert SSDLC reviewer.

Review Type:
{review_type}

Repository Files:

{file_text}

Select the 10 most security relevant files.

Return ONLY JSON.

Example:

[
    "app/auth.py",
    "routes/login.py"
]
"""

        try:
            result = QwenAgent.generate(prompt)
            return json.loads(result)

        except Exception:
            return files[:10]

    @staticmethod
    def summarize(findings):

        prompt = f"""
Generate an executive summary for management.

Findings:

{json.dumps(findings, indent=2)}

Include:

Overall Risk

Critical Issues

Business Impact

Top Recommendations

Keep under 300 words.
"""

        try:
            return QwenAgent.generate(prompt)

        except Exception:
            return "Executive summary unavailable."