import os
from dotenv import load_dotenv
from google import genai

load_dotenv()

client = genai.Client(
    api_key=os.getenv("GEMINI_API_KEY")
)

def generate_summary(
    findings,
    sources,
    validations,
    sinks
):

    prompt = f"""
Generate an executive cybersecurity review.

Sources Found: {sources}
Validations Found: {validations}
Sinks Found: {sinks}
Findings Count: {len(findings)}

Provide:

1. Overall Risk Rating
2. Key Observations
3. Top Recommendations

Keep under 200 words.
"""

    try:

        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt
        )

        return response.text

    except Exception as e:
        return f"Summary Generation Failed: {e}"