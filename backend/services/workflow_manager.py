"""
Enterprise Workflow Manager for ReBIT AI SSDLC Review Platform

Manages the 7-stage progressive review workflow:
1. Repository Details
2. Repository Analysis  
3. Relevant Files
4. Relevant Code Snippets
5. Security Findings
6. AI Reasoning
7. Final Report
"""
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from enum import Enum
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class ScanStage(Enum):
    """Enumeration of scan stages."""
    REPOSITORY_DETAILS = "Repository Details"
    REPOSITORY_ANALYSIS = "Repository Analysis"
    RELEVANT_FILES = "Relevant Files"
    RELEVANT_SNIPPETS = "Relevant Code Snippets"
    SECURITY_FINDINGS = "Security Findings"
    AI_REASONING = "AI Reasoning"
    FINAL_REPORT = "Final Report"


class ScanStatus(Enum):
    """Enumeration of scan lifecycle states."""
    DRAFT = "Draft"
    QUEUED = "Queued"
    RUNNING = "Running"
    COMPLETED = "Completed"
    FAILED = "Failed"
    CANCELLED = "Cancelled"


class WorkflowManager:
    """
    Manages the enterprise security review workflow.
    
    Tracks progress through 7 stages, manages state transitions,
    and provides structured data for each stage.
    """
    
    def __init__(self, scan_id: str, repository_url: str, user: str):
        """
        Initialize a new workflow instance.
        
        Args:
            scan_id: Unique identifier for this scan
            repository_url: URL of the repository to scan
            user: Username who initiated the scan
        """
        self.scan_id = scan_id
        self.repository_url = repository_url
        self.user = user
        self.status = ScanStatus.DRAFT
        self.current_stage: Optional[ScanStage] = None
        self.stages_completed: List[ScanStage] = []
        self.stage_data: Dict[str, Any] = {}
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.error_message: Optional[str] = None
        self.metadata: Dict[str, Any] = {
            "repository_name": "",
            "language": "",
            "framework": "",
            "review_types": [],
            "files_scanned": 0,
            "relevant_files_count": 0,
            "relevant_snippets_count": 0,
            "risk_score": 0,
            "scanner_versions": {},
            "ai_model_used": ""
        }
        
    def start(self) -> None:
        """Transition workflow from Draft to Running."""
        if self.status == ScanStatus.DRAFT:
            self.status = ScanStatus.RUNNING
            self.started_at = datetime.now()
            self.current_stage = ScanStage.REPOSITORY_DETAILS
            logger.info(f"Workflow {self.scan_id} started")
            
    def advance_stage(self, stage: ScanStage, data: Dict[str, Any]) -> None:
        """
        Complete current stage and advance to next.
        
        Args:
            stage: The stage being completed
            data: Data produced by this stage
        """
        if self.status != ScanStatus.RUNNING:
            raise ValueError(f"Cannot advance stage when status is {self.status}")
            
        self.stage_data[stage.value] = data
        self.stages_completed.append(stage)
        
        # Advance to next stage
        all_stages = list(ScanStage)
        current_idx = all_stages.index(stage)
        
        if current_idx < len(all_stages) - 1:
            self.current_stage = all_stages[current_idx + 1]
            logger.info(f"Workflow {self.scan_id} advanced to {self.current_stage.value}")
        else:
            # All stages complete
            self.complete()
            
    def complete(self) -> None:
        """Mark workflow as completed."""
        self.status = ScanStatus.COMPLETED
        self.completed_at = datetime.now()
        self.current_stage = None
        logger.info(f"Workflow {self.scan_id} completed")
        
    def fail(self, error_message: str, failed_stage: ScanStage) -> None:
        """
        Mark workflow as failed.
        
        Args:
            error_message: Description of the failure
            failed_stage: Stage where failure occurred
        """
        self.status = ScanStatus.FAILED
        self.error_message = error_message
        self.current_stage = failed_stage
        logger.error(f"Workflow {self.scan_id} failed at {failed_stage.value}: {error_message}")
        
    def cancel(self) -> None:
        """Cancel the workflow."""
        if self.status == ScanStatus.RUNNING:
            self.status = ScanStatus.CANCELLED
            logger.info(f"Workflow {self.scan_id} cancelled")
            
    def get_progress_percentage(self) -> int:
        """Calculate completion percentage."""
        if not self.stages_completed:
            return 0
        total_stages = len(ScanStage)
        return int((len(self.stages_completed) / total_stages) * 100)
    
    def get_stage_status(self, stage: ScanStage) -> str:
        """
        Get status of a specific stage.
        
        Returns: 'completed', 'current', 'pending', or 'failed'
        """
        if stage in self.stages_completed:
            return "completed"
        elif self.current_stage == stage:
            return "current"
        elif self.status == ScanStatus.FAILED and stage == self.current_stage:
            return "failed"
        else:
            return "pending"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert workflow state to dictionary."""
        return {
            "scan_id": self.scan_id,
            "repository_url": self.repository_url,
            "user": self.user,
            "status": self.status.value,
            "current_stage": self.current_stage.value if self.current_stage else None,
            "stages_completed": [s.value for s in self.stages_completed],
            "stage_data": self.stage_data,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error_message": self.error_message,
            "metadata": self.metadata,
            "progress_percentage": self.get_progress_percentage()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'WorkflowManager':
        """Reconstruct workflow from dictionary."""
        workflow = cls(
            scan_id=data["scan_id"],
            repository_url=data["repository_url"],
            user=data["user"]
        )
        workflow.status = ScanStatus(data["status"])
        workflow.stages_completed = [
            ScanStage(s) for s in data.get("stages_completed", [])
        ]
        workflow.current_stage = (
            ScanStage(data["current_stage"]) 
            if data.get("current_stage") 
            else None
        )
        workflow.stage_data = data.get("stage_data", {})
        workflow.started_at = (
            datetime.fromisoformat(data["started_at"]) 
            if data.get("started_at") 
            else None
        )
        workflow.completed_at = (
            datetime.fromisoformat(data["completed_at"]) 
            if data.get("completed_at") 
            else None
        )
        workflow.error_message = data.get("error_message")
        workflow.metadata = data.get("metadata", {})
        return workflow
    
    def update_metadata(self, updates: Dict[str, Any]) -> None:
        """Update workflow metadata."""
        self.metadata.update(updates)
        
    def get_relevant_files_with_scores(self) -> List[Dict[str, Any]]:
        """
        Get relevant files with relevance scores.
        
        Returns list of files with:
        - File path
        - Relevance score (%)
        - Reason selected
        - Number of findings
        - Functions reviewed
        """
        files_data = self.stage_data.get(ScanStage.RELEVANT_FILES.value, {})
        return files_data.get("files", [])
    
    def get_snippets_with_traceability(self) -> List[Dict[str, Any]]:
        """
        Get code snippets with full traceability.
        
        Each snippet includes:
        - Repository
        - File
        - Function
        - Start/End line
        - Highlighted snippet
        - Link to view full file
        """
        snippets_data = self.stage_data.get(ScanStage.RELEVANT_SNIPPETS.value, {})
        return snippets_data.get("snippets", [])
    
    def get_findings_with_filters(self) -> List[Dict[str, Any]]:
        """
        Get security findings with filterable metadata.
        
        Supports filtering by:
        - Severity
        - Review Type
        - OWASP Category
        - ASVS Category
        - CWE
        - Confidence
        """
        findings_data = self.stage_data.get(ScanStage.SECURITY_FINDINGS.value, {})
        return findings_data.get("findings", [])
    
    def get_ai_reasoning(self) -> Dict[str, Any]:
        """Get AI reasoning results."""
        return self.stage_data.get(ScanStage.AI_REASONING.value, {})
    
    def get_final_report_data(self) -> Dict[str, Any]:
        """Get consolidated data for final report generation."""
        return {
            "metadata": self.metadata,
            "repository_analysis": self.stage_data.get(ScanStage.REPOSITORY_ANALYSIS.value, {}),
            "relevant_files": self.get_relevant_files_with_scores(),
            "snippets": self.get_snippets_with_traceability(),
            "findings": self.get_findings_with_filters(),
            "ai_reasoning": self.get_ai_reasoning(),
            "scan_duration": (
                (self.completed_at - self.started_at).total_seconds()
                if self.completed_at and self.started_at
                else 0
            )
        }


class WorkflowStore:
    """
    Persistent storage for workflow instances.
    
    Supports saving, loading, and querying workflows.
    """
    
    def __init__(self, storage_path: str = "workflows.json"):
        """
        Initialize workflow store.
        
        Args:
            storage_path: Path to JSON file for persistence
        """
        self.storage_path = Path(storage_path)
        self._ensure_storage_exists()
        
    def _ensure_storage_exists(self) -> None:
        """Create storage file if it doesn't exist."""
        if not self.storage_path.exists():
            self.storage_path.write_text("[]")
            
    def _load_workflows(self) -> List[Dict[str, Any]]:
        """Load all workflows from storage."""
        try:
            data = json.loads(self.storage_path.read_text())
            return data
        except (json.JSONDecodeError, FileNotFoundError):
            return []
            
    def _save_workflows(self, workflows: List[Dict[str, Any]]) -> None:
        """Save workflows to storage."""
        self.storage_path.write_text(json.dumps(workflows, indent=2))
        
    def save_workflow(self, workflow: WorkflowManager) -> None:
        """Save or update a workflow."""
        workflows = self._load_workflows()
        
        # Remove existing entry for this scan_id
        workflows = [w for w in workflows if w["scan_id"] != workflow.scan_id]
        
        # Add updated workflow
        workflows.append(workflow.to_dict())
        
        self._save_workflows(workflows)
        logger.debug(f"Saved workflow {workflow.scan_id}")
        
    def get_workflow(self, scan_id: str) -> Optional[WorkflowManager]:
        """Retrieve a workflow by scan ID."""
        workflows = self._load_workflows()
        
        for w in workflows:
            if w["scan_id"] == scan_id:
                return WorkflowManager.from_dict(w)
                
        return None
        
    def get_all_workflows(self) -> List[WorkflowManager]:
        """Retrieve all workflows."""
        workflows = self._load_workflows()
        return [WorkflowManager.from_dict(w) for w in workflows]
    
    def get_workflows_by_user(self, user: str) -> List[WorkflowManager]:
        """Retrieve workflows for a specific user."""
        all_workflows = self.get_all_workflows()
        return [w for w in all_workflows if w.user == user]
    
    def get_workflows_by_status(self, status: ScanStatus) -> List[WorkflowManager]:
        """Retrieve workflows with a specific status."""
        all_workflows = self.get_all_workflows()
        return [w for w in all_workflows if w.status == status]
    
    def get_workflows_by_repository(self, repo_url: str) -> List[WorkflowManager]:
        """Retrieve workflows for a specific repository."""
        all_workflows = self.get_all_workflows()
        return [w for w in all_workflows if w.repository_url == repo_url]
    
    def delete_workflow(self, scan_id: str) -> bool:
        """Delete a workflow."""
        workflows = self._load_workflows()
        initial_count = len(workflows)
        
        workflows = [w for w in workflows if w["scan_id"] != scan_id]
        
        if len(workflows) < initial_count:
            self._save_workflows(workflows)
            logger.info(f"Deleted workflow {scan_id}")
            return True
            
        return False
    
    def search_workflows(
        self,
        status: Optional[ScanStatus] = None,
        user: Optional[str] = None,
        repo_url: Optional[str] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None
    ) -> List[WorkflowManager]:
        """
        Search workflows with multiple filters.
        
        Args:
            status: Filter by status
            user: Filter by user
            repo_url: Filter by repository URL
            date_from: Filter by start date (inclusive)
            date_to: Filter by end date (inclusive)
            
        Returns:
            List of matching workflows
        """
        results = self.get_all_workflows()
        
        if status:
            results = [w for w in results if w.status == status]
            
        if user:
            results = [w for w in results if w.user == user]
            
        if repo_url:
            results = [w for w in results if w.repository_url == repo_url]
            
        if date_from:
            results = [
                w for w in results 
                if w.started_at and w.started_at >= date_from
            ]
            
        if date_to:
            results = [
                w for w in results 
                if w.started_at and w.started_at <= date_to
            ]
            
        return results
    
    def compare_workflows(self, scan_id_1: str, scan_id_2: str) -> Optional[Dict[str, Any]]:
        """
        Compare two workflows (e.g., historical scans).
        
        Returns comparison data including:
        - Risk score difference
        - New findings
        - Resolved findings
        - Files changed
        - OWASP/ASVS/CWE changes
        """
        w1 = self.get_workflow(scan_id_1)
        w2 = self.get_workflow(scan_id_2)
        
        if not w1 or not w2:
            return None
            
        report1 = w1.get_final_report_data()
        report2 = w2.get_final_report_data()
        
        # Calculate differences
        risk_diff = report2["metadata"].get("risk_score", 0) - report1["metadata"].get("risk_score", 0)
        
        findings1 = {f.get("finding_id") for f in report1.get("findings", [])}
        findings2 = {f.get("finding_id") for f in report2.get("findings", [])}
        
        new_findings = findings2 - findings1
        resolved_findings = findings1 - findings2
        
        return {
            "scan_1": scan_id_1,
            "scan_2": scan_id_2,
            "risk_score_difference": risk_diff,
            "new_findings_count": len(new_findings),
            "resolved_findings_count": len(resolved_findings),
            "new_findings": list(new_findings),
            "resolved_findings": list(resolved_findings),
            "duration_1": report1.get("scan_duration", 0),
            "duration_2": report2.get("scan_duration", 0),
            "timestamp_1": w1.completed_at.isoformat() if w1.completed_at else None,
            "timestamp_2": w2.completed_at.isoformat() if w2.completed_at else None
        }
