"""
AI Security Review Agent for ReBIT AI SSDLC Review Platform

This module transforms Qwen into an enterprise AI Security Review Agent that reasons
like an experienced application security reviewer. It analyzes repository context,
understands code, validates findings, and produces explainable security reviews.

DO NOT simply summarize tool outputs. The AI must:
- Analyze repository context
- Understand the code
- Validate findings  
- Produce explainable security reviews
"""
import os
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from dotenv import load_dotenv

try:
    from google import genai
    GOOGLE_AI_AVAILABLE = True
except ImportError:
    GOOGLE_AI_AVAILABLE = False

from backend.config import (
    GEMINI_API_KEY, 
    GEMINI_MODEL, 
    MAX_CHUNK_SIZE,
    ENABLE_AI_REVIEW
)
from backend.utils.logger import get_logger

load_dotenv()
logger = get_logger(__name__)


class AISecurityReviewAgent:
    """
    Enterprise AI Security Review Agent that reasons like an experienced 
    application security reviewer.
    
    This agent analyzes structured repository context and produces detailed,
    evidence-based security findings with OWASP mapping, severity analysis,
    and actionable remediation guidance.
    """
    
    # OWASP Top 10 2021 Mapping
    OWASP_TOP_10 = {
        "A01:2021": "Broken Access Control",
        "A02:2021": "Cryptographic Failures",
        "A03:2021": "Injection",
        "A04:2021": "Insecure Design",
        "A05:2021": "Security Misconfiguration",
        "A06:2021": "Vulnerable and Outdated Components",
        "A07:2021": "Identification and Authentication Failures",
        "A08:2021": "Software and Data Integrity Failures",
        "A09:2021": "Security Logging and Monitoring Failures",
        "A10:2021": "Server-Side Request Forgery (SSRF)"
    }
    
    # CWE Common Mappings
    CWE_MAPPINGS = {
        "SQL Injection": "CWE-89",
        "XSS": "CWE-79",
        "Path Traversal": "CWE-22",
        "Command Injection": "CWE-78",
        "XXE": "CWE-611",
        "SSRF": "CWE-918",
        "Insecure Deserialization": "CWE-502",
        "Hardcoded Credentials": "CWE-798",
        "Weak Cryptography": "CWE-327",
        "Missing Authentication": "CWE-306",
        "Broken Authorization": "CWE-284",
        "Sensitive Data Exposure": "CWE-200",
        "Improper Input Validation": "CWE-20"
    }
    
    def __init__(self, api_key: str = None, model: str = None):
        """
        Initialize the AI Security Review Agent.
        
        Args:
            api_key: Gemini API key (defaults to config)
            model: Model name (defaults to config)
        """
        self.api_key = api_key or GEMINI_API_KEY
        self.model = model or GEMINI_MODEL
        self.client = None
        
        if not ENABLE_AI_REVIEW:
            logger.warning("AI review is disabled in configuration")
            
        if GOOGLE_AI_AVAILABLE and self.api_key:
            try:
                self.client = genai.Client(api_key=self.api_key)
                logger.info(f"AI Security Review Agent initialized with model: {self.model}")
            except Exception as e:
                logger.error(f"Failed to initialize AI client: {e}")
        else:
            logger.warning("AI client not available - check API key and dependencies")
    
    def analyze_repository_context(
        self,
        repo_summary: Dict[str, Any],
        relevant_files: List[Dict[str, Any]],
        security_findings: List[Dict[str, Any]],
        dependency_info: Optional[Dict[str, Any]] = None,
        ast_analysis: Optional[Dict[str, Any]] = None,
        call_graph: Optional[Dict[str, Any]] = None,
        data_flow: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Perform comprehensive AI-powered security review of repository context.
        
        Args:
            repo_summary: Repository metadata (language, framework, architecture)
            relevant_files: List of relevant files with content snippets
            security_findings: Findings from static analysis tools
            dependency_info: Dependency vulnerability information
            ast_analysis: AST analysis results
            call_graph: Call graph information
            data_flow: Data flow analysis information
            
        Returns:
            Comprehensive security review with validated findings
        """
        logger.info("Starting AI-powered security review")
        
        if not self.client:
            return self._generate_fallback_review(
                repo_summary, 
                relevant_files, 
                security_findings
            )
        
        # Build structured prompt for AI reasoning
        prompt = self._build_security_review_prompt(
            repo_summary,
            relevant_files,
            security_findings,
            dependency_info,
            ast_analysis,
            call_graph,
            data_flow
        )
        
        try:
            logger.debug(f"Sending prompt to AI model ({len(prompt)} chars)")
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt
            )
            
            # Parse AI response into structured findings
            review_results = self._parse_ai_response(response.text)
            
            logger.info(f"AI review completed: {len(review_results.get('findings', []))} findings")
            return review_results
            
        except Exception as e:
            logger.error(f"AI security review failed: {e}")
            return self._generate_fallback_review(
                repo_summary,
                relevant_files,
                security_findings
            )
    
    def _build_security_review_prompt(
        self,
        repo_summary: Dict[str, Any],
        relevant_files: List[Dict[str, Any]],
        security_findings: List[Dict[str, Any]],
        dependency_info: Optional[Dict[str, Any]],
        ast_analysis: Optional[Dict[str, Any]],
        call_graph: Optional[Dict[str, Any]],
        data_flow: Optional[Dict[str, Any]]
    ) -> str:
        """
        Build a structured prompt for AI security reasoning.
        
        This prompt engineering ensures the AI:
        - Reasons step-by-step like a security expert
        - Validates findings before confirming them
        - Maps to OWASP/CWE standards
        - Provides evidence-based conclusions
        - Avoids hallucinations
        """
        
        # Prepare file context (limit to avoid token limits)
        file_context = self._prepare_file_context(relevant_files[:10])
        
        # Prepare tool findings summary
        findings_summary = self._prepare_findings_summary(security_findings[:50])
        
        prompt = f"""You are an enterprise AI Security Review Agent with expertise in application security.
Your task is to analyze the provided repository context and produce a comprehensive security review.

## REPOSITORY CONTEXT

### Repository Summary
- Language: {repo_summary.get('language', 'Unknown')}
- Framework: {repo_summary.get('framework', 'Unknown')}
- Review Type: {repo_summary.get('review_type', 'Comprehensive')}
- Architecture: {repo_summary.get('architecture', 'Not specified')}

### Relevant Files and Code Snippets
{file_context}

### Static Analysis Tool Findings
{findings_summary}

### Dependency Information
{json.dumps(dependency_info, indent=2) if dependency_info else 'No dependency information provided'}

### AST Analysis
{json.dumps(ast_analysis, indent=2) if ast_analysis else 'No AST analysis provided'}

## YOUR TASK

For EACH potential security issue you identify, you MUST provide:

1. **What is happening?** - Clear description of the issue
2. **Why is it a security problem?** - Security rationale
3. **Where exactly is the issue?** - File, function, line numbers
4. **How can an attacker exploit it?** - Attack scenario
5. **What is the business impact?** - Business consequences
6. **What is the technical impact?** - Technical consequences
7. **How should it be fixed?** - Specific remediation steps
8. **Why is the suggested fix secure?** - Security rationale for the fix

## FALSE POSITIVE VALIDATION

DO NOT blindly trust static analysis tool outputs. You must:
- Validate whether reported issues are likely real vulnerabilities
- If evidence is weak, mark as "Needs Manual Review" instead of confirmed
- Provide reasoning for any uncertainty
- Cite specific code evidence from the provided context

## STANDARDS MAPPING

For each CONFIRMED issue, map to:
- OWASP Top 10 2021 (specify which one and why)
- OWASP ASVS (relevant requirements)
- CWE (specific CWE ID)
- MITRE ATT&CK (if applicable)

## SEVERITY ANALYSIS

For each issue determine:
- Severity: CRITICAL / HIGH / MEDIUM / LOW (use appropriately)
- Likelihood: HIGH / MEDIUM / LOW
- Impact: HIGH / MEDIUM / LOW  
- Confidence Score: 0-100%
- Business Risk: Description
- Technical Risk: Description

## OUTPUT FORMAT

Provide your analysis in the following structure:

```json
{{
  "executive_summary": {{
    "overall_security_score": "0-100",
    "critical_risks": [],
    "high_risks": [],
    "medium_risks": [],
    "low_risks": [],
    "positive_practices": [],
    "top_recommendations": []
  }},
  "findings": [
    {{
      "finding_id": "FINDING-001",
      "review_type": "Input Validation Review",
      "severity": "HIGH",
      "confidence_score": 85,
      "repository": "repo-name",
      "relevant_file": "/path/to/file.java",
      "relevant_function": "functionName",
      "line_numbers": [123, 124, 125],
      "code_snippet": "actual code here",
      "issue_description": "Clear description",
      "why_this_matters": "Security rationale",
      "business_impact": "Business consequences",
      "technical_impact": "Technical consequences",
      "attack_scenario": "How attackers could exploit",
      "owasp_mapping": ["A03:2021 - Injection"],
      "asvs_mapping": ["ASVS 5.1.1"],
      "cwe_mapping": ["CWE-89"],
      "mitre_attack": ["T1190"],
      "evidence": "Specific evidence from code",
      "recommended_fix": "Step-by-step remediation",
      "secure_code_example": "Example secure implementation",
      "references": ["https://..."]
    }}
  ],
  "developer_summary": {{
    "files_reviewed": [],
    "functions_reviewed": [],
    "issues_found": 0,
    "priority_fixes": [],
    "suggested_fixes": []
  }},
  "auditor_summary": {{
    "repository": "repo-name",
    "review_date": "2024-01-01",
    "review_type": "Comprehensive",
    "compliance_mapping": {{}},
    "risk_overview": {{}},
    "evidence": [],
    "conclusion": ""
  }}
}}
```

## IMPORTANT CONSTRAINTS

- NEVER invent files, functions, or vulnerabilities
- ALWAYS cite evidence from the provided code context
- Require evidence before drawing conclusions
- If uncertain, mark as "Needs Manual Review"
- Be precise about line numbers and file paths
- Focus on real security risks, not style issues

Begin your analysis now."""

        return prompt
    
    def _prepare_file_context(self, relevant_files: List[Dict[str, Any]]) -> str:
        """Prepare file context for the prompt, respecting token limits."""
        context_lines = []
        total_chars = 0
        max_chars = MAX_CHUNK_SIZE * 5  # Approximate limit for file context
        
        for file_info in relevant_files:
            file_path = file_info.get('file', 'unknown')
            snippet = file_info.get('snippet', '')
            
            # Truncate very long snippets
            if len(snippet) > 1000:
                snippet = snippet[:500] + "\n... [truncated] ...\n" + snippet[-500:]
            
            context_lines.append(f"File: {file_path}\n```{snippet}```\n")
            total_chars += len(context_lines[-1])
            
            if total_chars > max_chars:
                context_lines.append("... [additional files truncated due to size] ...")
                break
        
        return "\n".join(context_lines) if context_lines else "No file context provided"
    
    def _prepare_findings_summary(self, security_findings: List[Dict[str, Any]]) -> str:
        """Prepare a summary of static analysis findings."""
        if not security_findings:
            return "No static analysis findings provided"
        
        summary_lines = []
        for i, finding in enumerate(security_findings[:50], 1):
            file = finding.get('file', 'unknown')
            line = finding.get('line', '?')
            issue = finding.get('issue', 'Unknown issue')
            severity = finding.get('severity', 'MEDIUM')
            
            summary_lines.append(
                f"{i}. [{severity}] {issue} in {file}:{line}"
            )
        
        return "\n".join(summary_lines)
    
    def _parse_ai_response(self, response_text: str) -> Dict[str, Any]:
        """
        Parse AI response into structured review results.
        
        Attempts to extract JSON from the response, with fallback handling.
        """
        try:
            # Try to find JSON in the response
            start_idx = response_text.find('{')
            end_idx = response_text.rfind('}') + 1
            
            if start_idx >= 0 and end_idx > start_idx:
                json_str = response_text[start_idx:end_idx]
                review_data = json.loads(json_str)
                logger.info("Successfully parsed AI response as JSON")
                return review_data
            else:
                logger.warning("No JSON found in AI response, using fallback")
                return self._create_structured_review_from_text(response_text)
                
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI response JSON: {e}")
            return self._create_structured_review_from_text(response_text)
        except Exception as e:
            logger.error(f"Unexpected error parsing AI response: {e}")
            return self._create_structured_review_from_text(response_text)
    
    def _create_structured_review_from_text(self, response_text: str) -> Dict[str, Any]:
        """Create a structured review from unstructured AI text response."""
        return {
            "executive_summary": {
                "overall_security_score": "Analysis needed",
                "critical_risks": [],
                "high_risks": [],
                "medium_risks": [],
                "low_risks": [],
                "positive_practices": [],
                "top_recommendations": ["Manual review required"]
            },
            "findings": [],
            "developer_summary": {
                "files_reviewed": [],
                "functions_reviewed": [],
                "issues_found": 0,
                "priority_fixes": [],
                "suggested_fixes": []
            },
            "auditor_summary": {
                "repository": "Unknown",
                "review_date": datetime.now().isoformat(),
                "review_type": "AI Review",
                "compliance_mapping": {},
                "risk_overview": {},
                "evidence": [],
                "conclusion": response_text[:500] + "..." if len(response_text) > 500 else response_text
            },
            "raw_ai_analysis": response_text
        }
    
    def _generate_fallback_review(
        self,
        repo_summary: Dict[str, Any],
        relevant_files: List[Dict[str, Any]],
        security_findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate a fallback review when AI is not available."""
        logger.warning("Generating fallback review without AI analysis")
        
        return {
            "executive_summary": {
                "overall_security_score": "Pending AI Review",
                "critical_risks": [],
                "high_risks": [],
                "medium_risks": [],
                "low_risks": [],
                "positive_practices": [],
                "top_recommendations": [
                    "Enable AI review for comprehensive analysis",
                    "Review static analysis findings manually",
                    "Ensure proper security testing procedures"
                ]
            },
            "findings": [],
            "developer_summary": {
                "files_reviewed": [f.get('file', 'unknown') for f in relevant_files[:10]],
                "functions_reviewed": [],
                "issues_found": len(security_findings),
                "priority_fixes": [],
                "suggested_fixes": ["Manual code review recommended"]
            },
            "auditor_summary": {
                "repository": repo_summary.get('name', 'Unknown'),
                "review_date": datetime.now().isoformat(),
                "review_type": repo_summary.get('review_type', 'Comprehensive'),
                "compliance_mapping": {},
                "risk_overview": {
                    "total_findings": len(security_findings),
                    "ai_analysis_available": False
                },
                "evidence": [],
                "conclusion": "AI review unavailable. Manual security assessment recommended."
            },
            "metadata": {
                "ai_available": False,
                "fallback_mode": True,
                "timestamp": datetime.now().isoformat()
            }
        }
    
    def validate_finding(
        self,
        finding: Dict[str, Any],
        code_context: str
    ) -> Dict[str, Any]:
        """
        Validate a single finding using AI reasoning.
        
        This helps reduce false positives by having the AI assess
        whether a reported issue is likely a real vulnerability.
        
        Args:
            finding: The security finding to validate
            code_context: Relevant code context
            
        Returns:
            Validated finding with confidence assessment
        """
        if not self.client:
            finding['validation_status'] = 'PENDING_MANUAL_REVIEW'
            finding['confidence_score'] = 50
            finding['validation_note'] = 'AI validation unavailable'
            return finding
        
        prompt = f"""You are a security expert validating a potential vulnerability.

FINDING TO VALIDATE:
- Issue: {finding.get('issue', 'Unknown')}
- File: {finding.get('file', 'Unknown')}
- Line: {finding.get('line', 'Unknown')}
- Severity: {finding.get('severity', 'MEDIUM')}

CODE CONTEXT:
```{code_context[:2000]}```

TASK:
1. Is this a REAL vulnerability or a FALSE POSITIVE?
2. What evidence supports your conclusion?
3. Rate your confidence (0-100%)
4. Should this be marked as "Confirmed", "Likely", "Unlikely", or "False Positive"?

Respond in JSON format:
{{
  "is_real_vulnerability": true/false,
  "confidence_score": 0-100,
  "validation_status": "Confirmed/Likely/Unlikely/False Positive",
  "evidence": "specific evidence",
  "reasoning": "your analysis"
}}"""

        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt
            )
            
            # Parse validation response
            validation = self._parse_validation_response(response.text)
            finding.update(validation)
            
            logger.info(f"Finding validated: {finding.get('validation_status', 'Unknown')}")
            return finding
            
        except Exception as e:
            logger.error(f"Finding validation failed: {e}")
            finding['validation_status'] = 'PENDING_MANUAL_REVIEW'
            finding['confidence_score'] = 50
            finding['validation_note'] = f'Validation error: {str(e)}'
            return finding
    
    def _parse_validation_response(self, response_text: str) -> Dict[str, Any]:
        """Parse AI validation response."""
        try:
            start_idx = response_text.find('{')
            end_idx = response_text.rfind('}') + 1
            
            if start_idx >= 0 and end_idx > start_idx:
                json_str = response_text[start_idx:end_idx]
                return json.loads(json_str)
        except Exception:
            pass
        
        return {
            "validation_status": "PENDING_MANUAL_REVIEW",
            "confidence_score": 50,
            "reasoning": "Could not parse validation response"
        }


# Convenience function for quick AI review
def perform_ai_security_review(
    repo_summary: Dict[str, Any],
    relevant_files: List[Dict[str, Any]],
    security_findings: List[Dict[str, Any]],
    **kwargs
) -> Dict[str, Any]:
    """
    Perform an AI-powered security review.
    
    This is a convenience function that creates an agent and performs the review.
    
    Args:
        repo_summary: Repository metadata
        relevant_files: List of relevant files with snippets
        security_findings: Findings from static analysis tools
        **kwargs: Additional arguments passed to the agent
        
    Returns:
        Comprehensive security review results
    """
    agent = AISecurityReviewAgent()
    return agent.analyze_repository_context(
        repo_summary=repo_summary,
        relevant_files=relevant_files,
        security_findings=security_findings,
        **kwargs
    )
