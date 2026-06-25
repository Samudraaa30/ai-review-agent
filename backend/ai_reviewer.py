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


def review_finding(finding: dict) -> dict:
    prompt = f"""
You are an expert cybersecurity code reviewer.

Analyze the following security finding.

Finding:
{json.dumps(finding, indent=2)}

Return ONLY valid JSON in this exact format:

{{
    "risk": "...",
    "impact": "...",
    "remediation": "...",
    "severity": "...",
    "owasp": "...",
    "asvs": "...",
    "confidence": 95
}}

Do not use markdown.
Return only valid JSON.
"""

    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {
                    "role": "system",
                    "content": "You are an OWASP ASVS cybersecurity expert."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.2,
            max_tokens=600,
        )

        text = response.choices[0].message.content.strip()

        # Remove markdown code fences if present
        if text.startswith("```"):
            lines = text.splitlines()
            text = "\n".join(lines[1:-1]).strip()

        return json.loads(text)

    except Exception as e:
        return {
            "risk": "AI Review Failed",
            "impact": str(e),
            "remediation": "Verify your OpenRouter API key, model name, and internet connection.",
            "severity": finding.get("severity", "UNKNOWN"),
            "owasp": "",
            "asvs": "",
            "confidence": 0,
        }