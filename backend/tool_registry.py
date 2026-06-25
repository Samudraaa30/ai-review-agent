"""
Tool Registry Module

Registers and manages security tools for different review types.
"""
from backend.tools.input_validation_tool import InputValidationTool
from backend.tools.secrets_tool import SecretsTool
from backend.tools.auth_tool import AuthTool
from backend.utils.logger import get_logger

logger = get_logger(__name__)

# Registered security tools by review type
TOOLS = {
    "Input Validation": InputValidationTool(),
    "Secrets Detection": SecretsTool(),
    "Authentication Review": AuthTool()
}

logger.info(f"Registered {len(TOOLS)} security tools")