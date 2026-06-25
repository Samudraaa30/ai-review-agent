"""
ReBIT AI SSDLC Review Platform - Core Workflow Engine
Handles the 7-stage review process, Qwen AI integration, and Role-Based Access.
"""

import os
import json
import time
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from enum import Enum
from dataclasses import dataclass, asdict
import hashlib

# Configure Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Enums & Data Models ---

class ReviewStatus(Enum):
    PENDING = "Pending"
    RUNNING = "Running"
    COMPLETED = "Completed"
    FAILED = "Failed"
    REJECTED = "Rejected"
    APPROVED = "Approved"

class ReviewStage(Enum):
    INIT = "Repository Intelligence"
    FILES = "Relevant Files"
    FUNCTIONS = "Relevant Functions"
    SNIPPETS = "Relevant Code Snippets"
    TOOLS = "Security Tool Findings"
    AI_REASONING = "Qwen AI Reasoning"
    FINAL = "Executive Summary & Report"

@dataclass
class RelevantFile:
    path: str
    relevance_score: float
    reason: str
    findings_count: int
    functions_reviewed: List[str]

@dataclass
class CodeSnippet:
    file_path: str
    function_name: str
    start_line: int
    end_line: int
    code: str
    vulnerability_type: str

@dataclass
class AIFinding:
    id: str
    severity: str
    title: str
    description: str
    why_vulnerable: str
    business_impact: str
    technical_impact: str
    owasp_top10: str
    owasp_asvs: str
    cwe: str
    confidence_score: int
    recommendation: str
    snippet: CodeSnippet
    evidence: str

@dataclass
class RepositoryIntelligence:
    name: str
    url: str
    primary_language: str
    framework: str
    files_scanned: int
    relevant_files_count: int
    relevant_snippets_count: int
    dependencies: List[str]
    scan_duration: float

@dataclass
class ReviewSession:
    id: str
    user_email: str
    repo_url: str
    review_types: List[str]
    status: ReviewStatus
    current_stage: ReviewStage
    progress_percent: int
    created_at: str
    updated_at: str
    intelligence: Optional[RepositoryIntelligence]
    relevant_files: List[RelevantFile]
    snippets: List[CodeSnippet]
    findings: List[AIFinding]
    executive_summary: str
    risk_score: int
    manager_feedback: Optional[str]
    error_message: Optional[str]

# --- Mock Database (In-Memory for Demo Stability) ---
# In a real production app, this would be SQLite/PostgreSQL
review_store: Dict[str, ReviewSession] = {}

def generate_session_id(repo_url: str, user_email: str) -> str:
    timestamp = str(time.time())
    raw = f"{repo_url}{user_email}{timestamp}"
    return hashlib.md5(raw.encode()).hexdigest()[:12]

# --- Security Tool Simulators (Stable Mocks) ---

def run_bandit_mock(files: List[str]) -> List[Dict]:
    """Simulates Bandit output for demo stability."""
    findings = []
    if any("login" in f or "auth" in f for f in files):
        findings.append({
            "rule": "B106", "severity": "MEDIUM", "issue": "Hardcoded password",
            "file": next((f for f in files if "auth" in f), files[0]),
            "line": 15, "code": "password = 'admin123'"
        })
    if any("request" in f for f in files):
        findings.append({
            "rule": "B324", "severity": "HIGH", "issue": "Use of weak MD5 hash",
            "file": next((f for f in files if "hash" in f or "util" in f), files[0]),
            "line": 42, "code": "hashlib.md5(data)"
        })
    return findings

def run_semgrep_mock(files: List[str]) -> List[Dict]:
    """Simulates Semgrep output."""
    findings = []
    if any("api" in f for f in files):
        findings.append({
            "rule": "sql-injection", "severity": "CRITICAL", "issue": "SQL Injection risk",
            "file": next((f for f in files if "api" in f or "db" in f), files[0]),
            "line": 88, "code": "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')"
        })
    return findings

# --- Qwen AI Reasoning Engine ---

def generate_qwen_reasoning(tool_findings: List[Dict], files: List[str]) -> List[AIFinding]:
    """
    Transforms raw tool findings into enterprise-grade AI reasoning.
    Mimics Qwen's analysis without requiring an external API key for the demo.
    """
    ai_findings = []
    
    for finding in tool_findings:
        # Generate deterministic ID
        f_id = hashlib.md5(f"{finding['file']}{finding['line']}".encode()).hexdigest()[:8]
        
        # Enrich with Qwen-style reasoning
        ai_finding = AIFinding(
            id=f_id,
            severity=finding['severity'],
            title=finding['issue'],
            description=f"The code in {finding['file']} contains a potential {finding['issue']}.",
            why_vulnerable="The code lacks proper input validation and uses insecure patterns detected by static analysis.",
            business_impact="Could lead to unauthorized access, data breach, or system compromise depending on exploitability.",
            technical_impact="Attackers could execute arbitrary code, bypass authentication, or extract sensitive data.",
            owasp_top10="A03:2021 – Injection" if "SQL" in finding['issue'] else "A07:2021 – Identification and Authentication Failures",
            owasp_asvs="V5: Input Validation" if "SQL" in finding['issue'] else "V2: Authentication",
            cwe="CWE-89" if "SQL" in finding['issue'] else "CWE-259",
            confidence_score=92 if finding['severity'] == "CRITICAL" else 85,
            recommendation="Refactor to use parameterized queries and implement secure hashing algorithms.",
            snippet=CodeSnippet(
                file_path=finding['file'],
                function_name="process_request",
                start_line=finding['line'],
                end_line=finding['line'] + 2,
                code=finding['code'],
                vulnerability_type=finding['issue']
            ),
            evidence=f"Detected by pattern matching on line {finding['line']}."
        )
        ai_findings.append(ai_finding)
    
    # Add a generic architectural finding if no tools fired (for demo completeness)
    if not ai_findings:
        ai_findings.append(AIFinding(
            id="arch-01",
            severity="LOW",
            title="Missing Security Headers",
            description="No security headers detected in configuration files.",
            why_vulnerable="Default configurations often omit protective headers.",
            business_impact="Increased risk of XSS and Clickjacking attacks.",
            technical_impact="Browser-side vulnerabilities may be exploitable.",
            owasp_top10="A05:2021 – Security Misconfiguration",
            owasp_asvs="V7: Error Handling and Logging",
            cwe="CWE-693",
            confidence_score=75,
            recommendation="Add Content-Security-Policy and X-Frame-Options headers.",
            snippet=CodeSnippet(
                file_path="config/nginx.conf",
                function_name="server_block",
                start_line=10,
                end_line=12,
                code="server {\n    listen 80;\n}",
                vulnerability_type="Misconfiguration"
            ),
            evidence="Configuration file analysis."
        ))
        
    return ai_findings

# --- Main Workflow Manager ---

class WorkflowManager:
    @staticmethod
    def start_review(repo_url: str, user_email: str, review_types: List[str]) -> ReviewSession:
        session_id = generate_session_id(repo_url, user_email)
        
        session = ReviewSession(
            id=session_id,
            user_email=user_email,
            repo_url=repo_url,
            review_types=review_types,
            status=ReviewStatus.RUNNING,
            current_stage=ReviewStage.INIT,
            progress_percent=10,
            created_at=datetime.now().isoformat(),
            updated_at=datetime.now().isoformat(),
            intelligence=None,
            relevant_files=[],
            snippets=[],
            findings=[],
            executive_summary="",
            risk_score=0,
            manager_feedback=None,
            error_message=None
        )
        review_store[session_id] = session
        return session

    @staticmethod
    def execute_pipeline(session_id: str) -> ReviewSession:
        """Executes the full 7-stage pipeline synchronously for the demo."""
        if session_id not in review_store:
            raise ValueError("Session not found")
        
        session = review_store[session_id]
        try:
            # Stage 1: Repository Intelligence
            session.current_stage = ReviewStage.INIT
            session.progress_percent = 15
            # Mock Intelligence Data
            session.intelligence = RepositoryIntelligence(
                name=session.repo_url.split("/")[-1],
                url=session.repo_url,
                primary_language="Python",
                framework="Flask/FastAPI",
                files_scanned=45,
                relevant_files_count=5,
                relevant_snippets_count=8,
                dependencies=["requests==2.28.0", "flask==2.0.1", "numpy==1.21.0"],
                scan_duration=2.4
            )
            review_store[session_id] = session
            time.sleep(0.5) # Simulate work

            # Stage 2 & 3: Relevant Files & Functions
            session.current_stage = ReviewStage.FILES
            session.progress_percent = 35
            session.relevant_files = [
                RelevantFile("app/auth.py", 95.5, "Contains authentication logic", 2, ["login", "verify_token"]),
                RelevantFile("app/api/users.py", 88.2, "Direct database interaction", 1, ["get_user"]),
                RelevantFile("utils/crypto.py", 76.0, "Cryptographic operations", 1, ["hash_password"])
            ]
            review_store[session_id] = session
            time.sleep(0.5)

            # Stage 4: Snippets
            session.current_stage = ReviewStage.SNIPPETS
            session.progress_percent = 50
            # Snippets extracted based on files above
            session.snippets = [
                CodeSnippet("app/auth.py", "login", 15, 17, "password = 'admin123'", "Hardcoded Secret"),
                CodeSnippet("app/api/users.py", "get_user", 88, 90, "cursor.execute(f'SELECT...')", "SQL Injection")
            ]
            review_store[session_id] = session
            time.sleep(0.5)

            # Stage 5: Security Tools
            session.current_stage = ReviewStage.TOOLS
            session.progress_percent = 65
            file_paths = [f.path for f in session.relevant_files]
            raw_findings = run_bandit_mock(file_paths) + run_semgrep_mock(file_paths)
            review_store[session_id] = session
            time.sleep(0.5)

            # Stage 6: Qwen AI Reasoning
            session.current_stage = ReviewStage.AI_REASONING
            session.progress_percent = 85
            session.findings = generate_qwen_reasoning(raw_findings, file_paths)
            
            # Calculate Risk Score
            critical = sum(1 for f in session.findings if f.severity == "CRITICAL")
            high = sum(1 for f in session.findings if f.severity == "HIGH")
            session.risk_score = min(100, (critical * 30) + (high * 15))
            review_store[session_id] = session
            time.sleep(0.5)

            # Stage 7: Final Report
            session.current_stage = ReviewStage.FINAL
            session.progress_percent = 100
            session.status = ReviewStatus.COMPLETED
            session.executive_summary = (
                f"Security review completed for {session.intelligence.name}. "
                f"Identified {len(session.findings)} potential vulnerabilities. "
                f"Overall Risk Score: {session.risk_score}/100. "
                "Immediate attention required for SQL Injection and Hardcoded Secrets."
            )
            session.updated_at = datetime.now().isoformat()
            review_store[session_id] = session
            
            logger.info(f"Review {session_id} completed successfully.")
            return session

        except Exception as e:
            session.status = ReviewStatus.FAILED
            session.error_message = str(e)
            session.updated_at = datetime.now().isoformat()
            review_store[session_id] = session
            logger.error(f"Review {session_id} failed: {e}")
            return session

    @staticmethod
    def get_all_reviews(user_email: str, role: str) -> List[ReviewSession]:
        """Filter reviews based on role."""
        all_reviews = list(review_store.values())
        if role == "Developer":
            return [r for r in all_reviews if r.user_email == user_email]
        elif role == "Manager":
            return all_reviews # Manager sees all
        return []

    @staticmethod
    def approve_review(session_id: str, feedback: str) -> bool:
        if session_id in review_store:
            session = review_store[session_id]
            session.status = ReviewStatus.APPROVED
            session.manager_feedback = feedback
            session.updated_at = datetime.now().isoformat()
            return True
        return False

    @staticmethod
    def reject_review(session_id: str, feedback: str) -> bool:
        if session_id in review_store:
            session = review_store[session_id]
            session.status = ReviewStatus.REJECTED
            session.manager_feedback = feedback
            session.updated_at = datetime.now().isoformat()
            return True
        return False
