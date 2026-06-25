"""
Qwen AI Gateway
Centralized LLM interface for the ReBIT AI SSDLC Review Platform.
"""

import json
import os
import requests
from dotenv import load_dotenv

load_dotenv()

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
MODEL = os.getenv("LLM_MODEL", "qwen2.5-coder:7b")


class QwenAgent:

    @staticmethod
    def generate(prompt: str) -> str:
        """
        Send a prompt to the local Qwen model.
        """

        response = requests.post(
            f"{OLLAMA_HOST}/api/generate",
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False
            },
            timeout=300
        )

        response.raise_for_status()

        return response.json()["response"]

    @staticmethod
    def review_finding(finding: dict) -> dict:

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

            return {

                "risk": "AI Review Failed",

                "business_impact": str(e),

                "technical_impact": "",

                "owasp": "",

                "asvs": "",

                "recommendation": "Verify Ollama and Qwen model.",

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