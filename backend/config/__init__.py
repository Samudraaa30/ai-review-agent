"""
Configuration module for ReBIT AI SSDLC Review Platform

Centralized configuration management with environment variable support.
All hardcoded values should be moved here.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# =============================================================================
# Base Directories
# =============================================================================
BASE_DIR = Path(__file__).parent.parent.parent
BACKEND_DIR = Path(__file__).parent
FRONTEND_DIR = BASE_DIR / "frontend"
REPOS_DIR = BASE_DIR / "repos"
REPORTS_DIR = BASE_DIR / "reports"
FINDINGS_DIR = BASE_DIR / "findings"

# Ensure directories exist
for directory in [REPOS_DIR, REPORTS_DIR, FINDINGS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# =============================================================================
# File Paths
# =============================================================================
USERS_FILE = BASE_DIR / "users.json"
REVIEWS_FILE = BASE_DIR / "reviews.json"
SCAN_HISTORY_FILE = BASE_DIR / "scan_history.json"
AUDIT_LOGS_FILE = BASE_DIR / "audit_logs.json"

# =============================================================================
# Supported File Extensions
# =============================================================================
SUPPORTED_EXTENSIONS = [".java", ".js", ".ts", ".py", ".php", ".html", ".css"]

# =============================================================================
# AI Configuration
# =============================================================================
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama2")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")

# =============================================================================
# Security Configuration
# =============================================================================
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRATION_MINUTES = int(os.getenv("JWT_EXPIRATION_MINUTES", "30"))

# Password hashing
PASSWORD_HASH_ALGORITHM = "sha256"  # Should use bcrypt in production

# =============================================================================
# Scan Configuration
# =============================================================================
MAX_FILES_PER_SCAN = int(os.getenv("MAX_FILES_PER_SCAN", "1000"))
MAX_CHUNK_SIZE = int(os.getenv("MAX_CHUNK_SIZE", "5000"))
DEFAULT_CHUNK_SIZE = int(os.getenv("DEFAULT_CHUNK_SIZE", "1000"))
MAX_SNIPPET_LINES = int(os.getenv("MAX_SNIPPET_LINES", "10"))

# =============================================================================
# Risk Scoring Configuration
# =============================================================================
RISK_WEIGHTS = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1
}

SEVERITY_THRESHOLDS = {
    "CRITICAL": 16,
    "HIGH": 9,
    "MEDIUM": 4,
    "LOW": 0
}

# =============================================================================
# Report Configuration
# =============================================================================
REPORT_FORMATS = ["json", "html", "pdf"]
DEFAULT_REPORT_FORMAT = "html"
PDF_FONT_SIZE = int(os.getenv("PDF_FONT_SIZE", "10"))
HTML_THEME = os.getenv("HTML_THEME", "default")

# =============================================================================
# Logging Configuration
# =============================================================================
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_FILE = BASE_DIR / "rebit_platform.log"

# =============================================================================
# Database Configuration (Future)
# =============================================================================
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///rebit_platform.db")
DATABASE_POOL_SIZE = int(os.getenv("DATABASE_POOL_SIZE", "5"))

# =============================================================================
# Rate Limiting Configuration
# =============================================================================
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))

# =============================================================================
# Feature Flags
# =============================================================================
ENABLE_AI_REVIEW = os.getenv("ENABLE_AI_REVIEW", "true").lower() == "true"
ENABLE_SEMGREP = os.getenv("ENABLE_SEMGREP", "true").lower() == "true"
ENABLE_GITLEAKS = os.getenv("ENABLE_GITLEAKS", "true").lower() == "true"
ENABLE_NPM_AUDIT = os.getenv("ENABLE_NPM_AUDIT", "true").lower() == "true"

# =============================================================================
# RBAC Configuration
# =============================================================================
DEFAULT_ROLE = "Developer"
AVAILABLE_ROLES = ["Developer", "Manager", "Auditor", "Admin"]

# =============================================================================
# Application Metadata
# =============================================================================
APP_NAME = "ReBIT AI SSDLC Review Platform"
APP_VERSION = "1.0.0"
APP_DESCRIPTION = "Enterprise AI-Powered SSDLC Security Review Agent"
