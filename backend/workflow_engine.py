import os
import json
import time
import logging
from datetime import datetime
import traceback
from typing import List, Dict, Any, Optional
from enum import Enum
from dataclasses import dataclass, asdict
import hashlib
import traceback

from jupyter_client import session

# Core application detectors
from backend.risk_score import calculate_risk_score
from backend.secret_detector import detect_secrets
from backend.validation_detector import detect_validations
from backend.source_detector import detect_sources
from backend.sink_detector import detect_sinks
from backend.auth_detector import detect_auth
from backend.authorization_detector import detect_authorization
from backend.dependency_detector import detect_dependencies
from backend.snippet_extractor import extract_relevant_snippets
from backend.qwen_agent import QwenAgent
from backend.clone_repo import clone_repository
from backend.ai_reasoning_agent import select_relevant_files_ai
from backend.report_generator import generate_report
from pathlib import Path

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
review_store: Dict[str, ReviewSession] = {}
REVIEWS_FILE = "reviews.json"
def save_reviews():

    data = []

    for review in review_store.values():
        data.append(asdict(review))

    with open(REVIEWS_FILE, "w") as f:
        json.dump(data, f, indent=4)

def load_reviews():

    global review_store

    if not os.path.exists(REVIEWS_FILE):
        return

    try:

        with open(REVIEWS_FILE, "r") as f:
            data = json.load(f)

        print(f"Loaded {len(data)} previous reviews.")

    except Exception as e:
        print(e)

def generate_session_id(repo_url: str, user_email: str) -> str:
    timestamp = str(time.time())
    raw = f"{repo_url}{user_email}{timestamp}"
    return hashlib.md5(raw.encode()).hexdigest()[:12]

# --- Security Tool Simulators (Stable Mocks) ---

import subprocess
import json
import traceback

def run_bandit(files_path):
    if not files_path:
        return []

    repo_root = files_path

    try:
        result = subprocess.run(
            ["bandit", "-r", repo_root, "-f", "json"],
            capture_output=True,
            text=True
        )

        # Print Bandit's stderr so we know why it failed
        if result.stderr:
            print("Bandit stderr:")
            print(result.stderr)

        # If Bandit didn't produce JSON, don't crash
        if not result.stdout.strip():
            print("Bandit returned no JSON.")
            return []

        try:
            report = json.loads(result.stdout)
        except json.JSONDecodeError:
            print("Invalid JSON returned by Bandit:")
            print(result.stdout)
            return []

        findings = []

        for issue in report.get("results", []):
            findings.append({
                "rule": issue.get("test_id", "BANDIT"),
                "severity": issue.get("issue_severity", "LOW"),
                "issue": issue.get("issue_text", "Security issue"),
                "file": issue.get("filename", ""),
                "line": issue.get("line_number", 0),
                "code": issue.get("code", "")
            })

        return findings

    except Exception:
        traceback.print_exc()
        return []

# --- Qwen AI Reasoning Engine ---

def generate_qwen_reasoning(tool_findings, files):

    ai_findings = []

    # Limit findings for demo
    tool_findings = tool_findings[:10]

    for finding in tool_findings:

        severity = finding.get("severity", "MEDIUM").upper()

        review = QwenAgent.review_finding(finding)

        ai_findings.append(
            AIFinding(
                id=hashlib.md5(
                    f"{finding.get('file','unknown')}{finding.get('line',0)}".encode()
                ).hexdigest()[:8],

                severity=severity,

                title=finding.get("issue", "Security Finding"),

                description=review["risk"],

                why_vulnerable=review["risk"],

                business_impact=review["business_impact"],

                technical_impact=review["technical_impact"],

                owasp_top10=review["owasp"],

                owasp_asvs=review["asvs"],

                cwe=finding.get("rule", ""),

                confidence_score=review["confidence"],

                recommendation=review["recommendation"],

                snippet=CodeSnippet(
                    file_path=finding.get("file", ""),
                    function_name="Unknown",
                    start_line=finding.get("line", 0),
                    end_line=finding.get("line", 0),
                    code=finding.get("code", ""),
                    vulnerability_type=finding.get("issue", "")
                ),

                evidence="Generated from static security analysis."
            )
        )

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
        repo_path = clone_repository(session.repo_url)
        
        try:
            # Stage 1: Repository Intelligence
            session.current_stage = ReviewStage.INIT
            session.progress_percent = 15
            
            scan_start = time.time()

            all_repo_files = [f for f in Path(repo_path).rglob("*") if f.is_file()]
            python_files = list(Path(repo_path).rglob("*.py"))
            java_files = list(Path(repo_path).rglob("*.java"))
            js_files = list(Path(repo_path).rglob("*.js"))
            ts_files = list(Path(repo_path).rglob("*.ts"))

            if len(java_files) > max(len(python_files), len(js_files), len(ts_files)):
                language = "Java"
            elif len(js_files) > max(len(python_files), len(java_files), len(ts_files)):
                language = "JavaScript"
            elif len(ts_files) > max(len(python_files), len(java_files), len(js_files)):
                language = "TypeScript"
            else:
                language = "Python"

            framework = "Unknown"
            if Path(repo_path, "package.json").exists():
                framework = "Node.js"
            elif Path(repo_path, "pom.xml").exists():
                framework = "Spring Boot"
            elif Path(repo_path, "requirements.txt").exists():
                framework = "Python"

            session.intelligence = RepositoryIntelligence(
                name=Path(repo_path).name,
                url=session.repo_url,
                primary_language=language,
                framework=framework,
                files_scanned=len(all_repo_files),
                relevant_files_count=len(session.relevant_files),
                relevant_snippets_count=len(session.snippets),
                dependencies=[],
                scan_duration=round(time.time() - scan_start, 2)
            )
            review_store[session_id] = session
            time.sleep(0.5)

            # Stage 2 & 3: Relevant Files & Functions
            session.current_stage = ReviewStage.FILES
            session.progress_percent = 35

            all_files = [str(f) for f in Path(repo_path).rglob("*") if f.is_file()]
            selected_files = select_relevant_files_ai(all_files, session.review_types[0])

            session.relevant_files = []
            for file in selected_files:
                session.relevant_files.append(
                    RelevantFile(
                        path=file,
                        relevance_score=90,
                        reason="Selected by Qwen AI",
                        findings_count=0,
                        functions_reviewed=[]
                    )
                )

            review_store[session_id] = session
            time.sleep(0.5)

            # Stage 4: Snippets
            session.current_stage = ReviewStage.SNIPPETS
            session.progress_percent = 50
            
            session.snippets = []
            selected_paths = [file.path for file in session.relevant_files]
            extracted_snippets = extract_relevant_snippets(selected_paths)

            for snippet in extracted_snippets:
                session.snippets.append(
                    CodeSnippet(
                        file_path=snippet["file"],
                        function_name="Unknown",
                        start_line=1,
                        end_line=20,
                        code=snippet["snippet"],
                        vulnerability_type="Unknown"
                    )
                )
            
            review_store[session_id] = session
            time.sleep(0.5)

            # Stage 5: Security Tools
            session.current_stage = ReviewStage.TOOLS
            session.progress_percent = 65
            file_paths = [f.path for f in session.relevant_files]

            raw_findings = []

            review_type = session.review_types[0]

            if review_type == "Input Validation":

             raw_findings.extend(detect_validations(repo_path))
             raw_findings.extend(detect_sources(repo_path))
             raw_findings.extend(detect_sinks(repo_path))

            elif review_type == "Secrets Detection":

             raw_findings.extend(detect_secrets(repo_path))

            elif review_type == "Authentication Review":

             raw_findings.extend(detect_auth(repo_path))

            elif review_type == "Authorization Review":

             raw_findings.extend(detect_authorization(repo_path))

            elif review_type == "Dependency Security":

             raw_findings.extend(detect_dependencies(repo_path))

            else:
    # Full Review / Fallback
             raw_findings.extend(run_bandit(repo_path))
             raw_findings.extend(detect_secrets(repo_path))
             raw_findings.extend(detect_auth(repo_path))
             raw_findings.extend(detect_authorization(repo_path))
             raw_findings.extend(detect_validations(repo_path))
             raw_findings.extend(detect_sources(repo_path))
             raw_findings.extend(detect_sinks(repo_path))
             raw_findings.extend(detect_dependencies(repo_path))
             
            session.risk_score = calculate_risk_score(raw_findings)

            review_store[session_id] = session
            time.sleep(0.5)

            # Stage 6: Qwen AI Reasoning
            session.current_stage = ReviewStage.AI_REASONING
            session.progress_percent = 85
            session.findings = generate_qwen_reasoning(raw_findings, file_paths)
            print("RAW FINDINGS:", len(raw_findings))
            print("AI FINDINGS:", len(session.findings))

            # Calculate Risk Score            
            review_store[session_id] = session
            time.sleep(0.5)

            # Stage 7: Final Report
            session.current_stage = ReviewStage.FINAL
            session.progress_percent = 100
            session.status = ReviewStatus.COMPLETED
            
            critical = sum(1 for f in session.findings if f.severity == "CRITICAL")
            high = sum(1 for f in session.findings if f.severity == "HIGH")
            medium = sum(1 for f in session.findings if f.severity == "MEDIUM")
            low = sum(1 for f in session.findings if f.severity == "LOW")

            session.executive_summary = f"""
            Repository Review Summary

            Overall Risk Score: {session.risk_score}/100

            Findings Summary:
            • Critical: {critical}
            • High: {high}
            • Medium: {medium}
            • Low: {low}

            Business Impact:
            The repository contains security findings that should be remediated before production deployment. Critical and High findings require immediate attention, while Medium and Low findings should be addressed during the development lifecycle.

            Top Recommendation:
            Prioritize remediation of Critical and High severity vulnerabilities, strengthen secure coding practices, and perform security validation before release.
            """
            
            generate_report(
             session_id=session.id,
             repository=session.intelligence.name if session.intelligence else "Unknown",
             findings=session.findings,
             risk_score=session.risk_score,
             summary=session.executive_summary
            )
            
            session.updated_at = datetime.now().isoformat()
            review_store[session_id] = session

            logger.info(f"Review {session_id} completed successfully.")
            return session

        except Exception as e:
           traceback.print_exc()
           
           session.status = ReviewStatus.FAILED
           session.error_message = str(e)
           session.updated_at = datetime.now().isoformat()
           review_store[session_id] = session
           logger.exception(f"Review {session_id} failed")
           return session

    @staticmethod
    def get_all_reviews(user_email: str, role: str) -> List[ReviewSession]:
        """Filter reviews based on role."""
        all_reviews = list(review_store.values())
        if role == "Developer":
            return [r for r in all_reviews if r.user_email == user_email]
        elif role == "Manager":
            return all_reviews  # Manager sees all
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
