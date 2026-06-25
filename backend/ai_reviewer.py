import json
import os

import requests
from dotenv import load_dotenv

load_dotenv()

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
LLM_MODEL = os.getenv("LLM_MODEL", "qwen2.5-coder:7b")


def review_finding(finding: dict) -> dict:
    """
    Sends a security finding to Qwen for AI reasoning.
    """

    prompt = f"""
You are an expert cybersecurity code reviewer.

Analyze the following security finding.

Finding:
{json.dumps(finding, indent=2)}

Return ONLY valid JSON in this format:

{{
    "risk": "...",
    "impact": "...",
    "remediation": "...",
    "severity": "...",
    "owasp": "...",
    "asvs": "...",
    "confidence": 95
}}

Do not include markdown.
Do not explain anything outside JSON.
"""

    try:
        response = requests.post(
            f"{OLLAMA_HOST}/api/generate",
            json={
                "model": LLM_MODEL,
                "prompt": prompt,
                "stream": False,
            },
            timeout=180,
        )

        response.raise_for_status()

        result = response.json()["response"].strip()

        return json.loads(result)

    except Exception as e:
        return {
            "risk": "AI Review Failed",
            "impact": str(e),
            "remediation": "Verify Ollama is running and the Qwen model is installed.",
            "severity": finding.get("severity", "UNKNOWN"),
            "owasp": "",
            "asvs": "",
            "confidence": 0,
        }