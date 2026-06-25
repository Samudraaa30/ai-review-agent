"""
AI Reasoning Agent Module

Provides AI-powered file selection using LLM models.
"""
import os
from typing import List
from dotenv import load_dotenv

try:
    from google import genai
    GOOGLE_AI_AVAILABLE = True
except ImportError:
    GOOGLE_AI_AVAILABLE = False

from backend.config import GEMINI_API_KEY, GEMINI_MODEL
from backend.utils.logger import get_logger

load_dotenv()
logger = get_logger(__name__)


def select_relevant_files_ai(
    files: List[str],
    review_type: str,
    max_files: int = 10
) -> str:
    """
    Use AI to select the most relevant files for a review type.
    
    Args:
        files: List of file paths to consider
        review_type: Type of security review
        max_files: Maximum number of files to select
    
    Returns:
        AI response with selected files or error message
    """
    if not GOOGLE_AI_AVAILABLE:
        logger.error("Google AI library not available")
        return "AI library not available"
    
    if not GEMINI_API_KEY:
        logger.error("Gemini API key not configured")
        return "API key not configured"
    
    try:
        client = genai.Client(api_key=GEMINI_API_KEY)
        
        file_list = "\n".join(files[:200])
        
        prompt = f"""
You are a cybersecurity review agent.

Review Type: {review_type}

Repository Files:
{file_list}

Select the {max_files} most relevant files for this security review.

Return only filenames, one per line.
"""
        
        logger.info(f"Requesting AI file selection for {review_type}")
        
        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt
        )
        
        logger.info(f"AI selected files for {review_type}")
        return response.text
        
    except Exception as e:
        logger.error(f"AI reasoning failed: {e}")
        return f"Reasoning Failed: {e}"