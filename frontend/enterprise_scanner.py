"""
Enterprise Security Scanner with 7-Stage Progressive Workflow

This module implements the structured enterprise review flow:
1. Repository Details
2. Repository Analysis
3. Relevant Files (with relevance scores)
4. Relevant Code Snippets (with traceability)
5. Security Findings (with filters)
6. AI Reasoning (Qwen)
7. Final Report
"""
import streamlit as st
import sys
from pathlib import Path
from datetime import datetime
import uuid

sys.path.append(str(Path(__file__).parent.parent))

from backend.clone_repo import clone_repository
from backend.repository_indexer import build_repository_index
from backend.language_detector import detect_language
from backend.reasoning_agent import select_relevant_files
from backend.snippet_extractor import extract_relevant_snippets
from backend.function_extractor import extract_functions
from backend.finding_engine import generate_findings
from backend.source_detector import detect_sources
from backend.validation_detector import detect_validations
from backend.sink_detector import detect_sinks
from backend.metrics import severity_counts
from backend.risk_score import calculate_risk_score
from backend.ai_reasoning_agent import select_relevant_files_ai
from backend.ast_analyzer import analyze_python_ast
from backend.java_ast import analyze_java
from backend.tool_runner import run_tool
from backend.scan_history import save_scan
from backend.review_store import load_reviews, save_reviews
from backend.pdf_report import generate_pdf_report
from backend.services.workflow_manager import (
    WorkflowManager,
    WorkflowStore,
    ScanStage,
    ScanStatus
)
from backend.ai.qwen_security_agent import AISecurityReviewAgent


def render_stage_indicator(workflow: WorkflowManager) -> None:
    """Render visual indicator of current stage."""
    stages = list(ScanStage)
    
    cols = st.columns(len(stages))
    
    for idx, stage in enumerate(stages):
        with cols[idx]:
            status = workflow.get_stage_status(stage)
            
            if status == "completed":
                st.success(f"✅ {stage.value}")
            elif status == "current":
                st.info(f"🔄 {stage.value}")
            elif status == "failed":
                st.error(f"❌ {stage.value}")
            else:
                st.write(f"⏳ {stage.value}")


def render_repository_details(workflow: WorkflowManager, repo_path: Path) -> dict:
    """Stage 1: Display repository details."""
    st.header("📁 Stage 1: Repository Details")
    
    # Build repository index
    repo_index = build_repository_index(repo_path)
    
    # Detect language
    language_info = detect_language(repo_path)
    
    data = {
        "repository_name": repo_path.name,
        "repository_path": str(repo_path),
        "language": language_info.get("language", "Unknown"),
        "framework": language_info.get("framework", "Unknown"),
        "total_files": repo_index.get("total_files", 0),
        "total_size_bytes": repo_index.get("total_size", 0),
        "file_types": repo_index.get("file_types", {})
    }
    
    # Update workflow metadata
    workflow.update_metadata({
        "repository_name": data["repository_name"],
        "language": data["language"],
        "framework": data["framework"],
        "files_scanned": data["total_files"]
    })
    
    # Display details
    col1, col2, col3 = st.columns(3)
    col1.metric("Language", data["language"])
    col2.metric("Framework", data["framework"])
    col3.metric("Total Files", data["total_files"])
    
    col4, col5 = st.columns(2)
    col4.metric("Repository Size", f"{data['total_size_bytes'] / 1024:.2f} KB")
    col5.metric("Repository Name", data["repository_name"])
    
    with st.expander("📂 File Types Distribution"):
        st.json(data["file_types"])
    
    return data


def render_repository_analysis(workflow: WorkflowManager, repo_path: Path, review_type: str) -> dict:
    """Stage 2: Perform repository analysis."""
    st.header("🔍 Stage 2: Repository Analysis")
    
    with st.spinner("Analyzing repository structure..."):
        # Run AST analysis
        ast_results = analyze_python_ast(repo_path)
        java_ast = analyze_java(repo_path)
        
        # Extract functions
        relevant_files = select_relevant_files(repo_path, review_type)
        all_functions = []
        for file_path in relevant_files[:10]:  # Limit for performance
            funcs = extract_functions(file_path)
            all_functions.extend(funcs)
        
        data = {
            "ast_analysis": ast_results,
            "java_ast": java_ast,
            "functions_count": len(all_functions),
            "relevant_files_count": len(relevant_files),
            "review_type": review_type
        }
        
        workflow.update_metadata({
            "relevant_files_count": len(relevant_files),
            "review_types": [review_type]
        })
        
        col1, col2 = st.columns(2)
        col1.metric("Functions Analyzed", data["functions_count"])
        col2.metric("Relevant Files", data["relevant_files_count"])
        
        with st.expander("🧠 AST Analysis Results"):
            st.json(ast_results)
    
    return data


def render_relevant_files(workflow: WorkflowManager, repo_path: Path, review_type: str) -> dict:
    """Stage 3: Display relevant files with relevance scores."""
    st.header("📄 Stage 3: Relevant Files")
    
    with st.spinner("Identifying relevant files..."):
        # Get files using AI reasoning
        all_files = [str(f) for f in repo_path.glob("**/*.py")] + \
                   [str(f) for f in repo_path.glob("**/*.java")] + \
                   [str(f) for f in repo_path.glob("**/*.js")]
        
        ai_reasoning = select_relevant_files_ai(all_files[:50], review_type)
        relevant_files = select_relevant_files(repo_path, review_type)
        
        # Calculate relevance scores (mock implementation - should use AI scoring)
        files_with_scores = []
        for idx, file_path in enumerate(relevant_files[:20]):  # Limit display
            # Mock relevance score based on position (should be AI-calculated)
            relevance_score = max(100 - (idx * 5), 50)
            
            files_with_scores.append({
                "file": str(file_path),
                "relevance_score": relevance_score,
                "reason_selected": f"Matched {review_type} patterns",
                "findings_count": 0,  # Will be updated after scanning
                "functions_reviewed": len(extract_functions(file_path))
            })
        
        data = {
            "files": files_with_scores,
            "ai_reasoning": ai_reasoning,
            "total_relevant": len(relevant_files)
        }
        
        workflow.update_metadata({
            "relevant_files_count": len(files_with_scores)
        })
        
        st.metric("Total Relevant Files", data["total_relevant"])
        
        # Display files sorted by relevance
        files_with_scores.sort(key=lambda x: x["relevance_score"], reverse=True)
        
        for file_info in files_with_scores:
            with st.expander(
                f"📄 {file_info['file']} (Score: {file_info['relevance_score']}%)"
            ):
                st.write(f"**Reason Selected:** {file_info['reason_selected']}")
                st.write(f"**Functions Reviewed:** {file_info['functions_reviewed']}")
                st.write(f"**Findings Count:** {file_info['findings_count']}")
                
                # Show file preview
                try:
                    with open(file_info['file'], 'r') as f:
                        preview = f.read()[:500]
                        st.code(preview + "...", language="python")
                except Exception as e:
                    st.error(f"Could not read file: {e}")
    
    return data


def render_relevant_snippets(workflow: WorkflowManager, repo_path: Path, review_type: str) -> dict:
    """Stage 4: Extract and display relevant code snippets with traceability."""
    st.header("✂️ Stage 4: Relevant Code Snippets")
    
    with st.spinner("Extracting code snippets..."):
        relevant_files = select_relevant_files(repo_path, review_type)
        snippets = extract_relevant_snippets(relevant_files[:10])
        
        # Add traceability information
        snippets_with_trace = []
        for snippet in snippets[:15]:  # Limit display
            snippets_with_trace.append({
                "repository": repo_path.name,
                "file": snippet.get("file", ""),
                "function": snippet.get("function", "N/A"),
                "start_line": snippet.get("start_line", 0),
                "end_line": snippet.get("end_line", 0),
                "snippet": snippet.get("snippet", ""),
                "view_full_file_link": snippet.get("file", "")
            })
        
        data = {
            "snippets": snippets_with_trace,
            "total_snippets": len(snippets)
        }
        
        workflow.update_metadata({
            "relevant_snippets_count": len(snippets_with_trace)
        })
        
        st.metric("Total Snippets Extracted", data["total_snippets"])
        
        for snippet in snippets_with_trace:
            with st.expander(
                f"📝 {snippet['file']}:{snippet['start_line']}-{snippet['end_line']} "
                f"({snippet['function']})"
            ):
                st.write(f"**Repository:** {snippet['repository']}")
                st.write(f"**Function:** {snippet['function']}")
                st.write(f"**Lines:** {snippet['start_line']} - {snippet['end_line']}")
                
                st.code(
                    snippet['snippet'],
                    language="python" if ".py" in snippet['file'] else "java"
                )
                
                st.info(f"📄 [View Full File](#{snippet['view_full_file_link']})")
    
    return data


def render_security_findings(
    workflow: WorkflowManager, 
    repo_path: Path, 
    review_type: str
) -> dict:
    """Stage 5: Generate and display security findings with filters."""
    st.header("🚨 Stage 5: Security Findings")
    
    with st.spinner("Running security analysis..."):
        # Run detectors based on review type
        sources = detect_sources(repo_path)
        validations = detect_validations(repo_path)
        sinks = detect_sinks(repo_path)
        
        findings = generate_findings(sources, validations, sinks)
        metrics = severity_counts(findings)
        
        # Add filterable metadata to each finding
        findings_with_metadata = []
        for idx, finding in enumerate(findings):
            findings_with_metadata.append({
                "finding_id": f"FINDING-{idx+1:03d}",
                "review_type": review_type,
                "severity": finding.get("severity", "MEDIUM"),
                "confidence_score": finding.get("confidence", 75),
                "repository": repo_path.name,
                "relevant_file": finding.get("file", ""),
                "relevant_function": finding.get("function", ""),
                "line_numbers": finding.get("lines", []),
                "code_snippet": finding.get("snippet", ""),
                "issue_description": finding.get("description", ""),
                "owasp_category": finding.get("owasp", "A03:2021 - Injection"),
                "asvs_category": finding.get("asvs", "ASVS 5.1.1"),
                "cwe": finding.get("cwe", "CWE-89"),
                "status": "Open"
            })
        
        data = {
            "findings": findings_with_metadata,
            "metrics": metrics,
            "sources_count": len(sources),
            "validations_count": len(validations),
            "sinks_count": len(sinks)
        }
        
        # Display metrics
        col1, col2, col3, col4 = st.columns(4)
        col1.error(f"🔴 Critical: {metrics.get('critical', 0)}")
        col2.warning(f"🟠 High: {metrics.get('high', 0)}")
        col3.info(f"🔵 Medium: {metrics.get('medium', 0)}")
        col4.success(f"🟢 Low: {metrics.get('low', 0)}")
        
        # Filters
        st.subheader("🔍 Filter Findings")
        
        filter_col1, filter_col2, filter_col3 = st.columns(3)
        
        with filter_col1:
            severity_filter = st.multiselect(
                "Severity",
                ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                default=["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            )
        
        with filter_col2:
            status_filter = st.multiselect(
                "Status",
                ["Open", "Closed", "Needs Manual Review"],
                default=["Open"]
            )
        
        with filter_col3:
            search_term = st.text_input("Search by filename or description")
        
        # Apply filters
        filtered_findings = findings_with_metadata
        
        if severity_filter:
            filtered_findings = [
                f for f in filtered_findings 
                if f["severity"] in severity_filter
            ]
        
        if search_term:
            filtered_findings = [
                f for f in filtered_findings
                if search_term.lower() in f["relevant_file"].lower() or
                   search_term.lower() in f["issue_description"].lower()
            ]
        
        st.write(f"**Showing {len(filtered_findings)} of {len(findings_with_metadata)} findings**")
        
        # Display findings
        for finding in filtered_findings:
            with st.expander(
                f"{'🔴' if finding['severity'] == 'CRITICAL' else '🟠' if finding['severity'] == 'HIGH' else '🔵'} "
                f"[{finding['severity']}] {finding['issue_description'][:50]}..."
            ):
                col1, col2, col3 = st.columns(3)
                col1.write(f"**ID:** {finding['finding_id']}")
                col2.write(f"**File:** {finding['relevant_file']}")
                col3.write(f"**Line:** {finding['line_numbers']}")
                
                st.write(f"**Description:** {finding['issue_description']}")
                st.write(f"**OWASP:** {finding['owasp_category']}")
                st.write(f"**CWE:** {finding['cwe']}")
                st.write(f"**Confidence:** {finding['confidence_score']}%")
                
                if finding['code_snippet']:
                    st.code(finding['code_snippet'], language="python")
    
    return data


def render_ai_reasoning(
    workflow: WorkflowManager, 
    repo_path: Path, 
    review_type: str,
    findings_data: dict
) -> dict:
    """Stage 6: AI reasoning with Qwen."""
    st.header("🤖 Stage 6: AI Security Reasoning")
    
    # Initialize AI agent
    ai_agent = AISecurityReviewAgent()
    
    with st.spinner("AI is analyzing findings and generating insights..."):
        # Prepare context for AI
        repo_summary = {
            "language": workflow.metadata.get("language", "Unknown"),
            "framework": workflow.metadata.get("framework", "Unknown"),
            "review_type": review_type,
            "architecture": "Not specified"
        }
        
        relevant_files = [
            {"file": f["file"], "snippet": f.get("snippet", "")}
            for f in workflow.stage_data.get(ScanStage.RELEVANT_SNIPPETS.value, {}).get("snippets", [])[:10]
        ]
        
        security_findings = findings_data.get("findings", [])[:20]
        
        # Run AI analysis
        ai_results = ai_agent.analyze_repository_context(
            repo_summary=repo_summary,
            relevant_files=relevant_files,
            security_findings=security_findings
        )
        
        data = {
            "executive_summary": ai_results.get("executive_summary", {}),
            "findings": ai_results.get("findings", []),
            "developer_summary": ai_results.get("developer_summary", {}),
            "auditor_summary": ai_results.get("auditor_summary", {})
        }
        
        # Display AI results
        exec_summary = data["executive_summary"]
        
        if exec_summary:
            score = exec_summary.get("overall_security_score", "N/A")
            st.metric("🎯 Overall Security Score", score)
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("🔴 Critical Risks")
                for risk in exec_summary.get("critical_risks", []):
                    st.write(f"- {risk}")
                
                st.subheader("🟠 High Risks")
                for risk in exec_summary.get("high_risks", []):
                    st.write(f"- {risk}")
            
            with col2:
                st.subheader("✅ Positive Practices")
                for practice in exec_summary.get("positive_practices", []):
                    st.write(f"- {practice}")
                
                st.subheader("💡 Top Recommendations")
                for rec in exec_summary.get("top_recommendations", []):
                    st.write(f"- {rec}")
        
        with st.expander("📋 Developer Summary"):
            st.json(data.get("developer_summary", {}))
        
        with st.expander("📊 Auditor Summary"):
            st.json(data.get("auditor_summary", {}))
    
    return data


def render_final_report(
    workflow: WorkflowManager,
    repo_url: str,
    review_type: str,
    all_data: dict
) -> dict:
    """Stage 7: Generate final report."""
    st.header("📊 Stage 7: Final Report")
    
    with st.spinner("Generating comprehensive report..."):
        # Calculate final risk score
        findings = all_data.get("findings", {}).get("findings", [])
        risk_score = calculate_risk_score(findings)
        
        # Update workflow metadata
        workflow.update_metadata({
            "risk_score": risk_score
        })
        
        # Generate summary
        from backend.executive_summary import generate_summary
        summary = generate_summary(
            findings,
            all_data.get("sources_count", 0),
            all_data.get("validations_count", 0),
            all_data.get("sinks_count", 0)
        )
        
        # Generate PDF report
        pdf_path = generate_pdf_report(
            f"report_{workflow.scan_id}.pdf",
            summary,
            findings,
            risk_score,
            all_data.get("metrics", {})
        )
        
        # Save scan history
        save_scan(repo_url, review_type, risk_score)
        
        # Save to review store
        reviews = load_reviews() or []
        reviews.append({
            "repo": repo_url,
            "review_type": review_type,
            "risk_score": risk_score,
            "pdf_path": pdf_path,
            "timestamp": datetime.now().strftime("%d-%m-%Y %H:%M"),
            "submitted_by": st.session_state.username,
            "status": "Pending",
            "manager_comment": "",
            "scan_id": workflow.scan_id
        })
        save_reviews(reviews)
        
        data = {
            "risk_score": risk_score,
            "pdf_path": pdf_path,
            "summary": summary,
            "findings_count": len(findings)
        }
        
        # Display results
        st.success("✅ Security Review Complete!")
        
        col1, col2, col3 = st.columns(3)
        col1.metric("Risk Score", data["risk_score"])
        col2.metric("Findings Found", data["findings_count"])
        col3.metric("Duration", f"{workflow.get_progress_percentage()}%")
        
        # Download buttons
        if pdf_path:
            try:
                with open(pdf_path, "rb") as pdf_file:
                    st.download_button(
                        "📄 Download PDF Report",
                        pdf_file,
                        file_name=f"Security_Report_{workflow.scan_id}.pdf",
                        mime="application/pdf"
                    )
            except Exception as e:
                st.error(f"Could not load PDF: {e}")
        
        # Save workflow
        workflow_store = WorkflowStore()
        workflow_store.save_workflow(workflow)
    
    return data


def main():
    """Main function for enterprise security scanner page."""
    st.set_page_config(
        page_title="Enterprise Security Scanner",
        page_icon="🔒",
        layout="wide"
    )
    
    st.title("🔒 Enterprise Security Scanner")
    st.markdown("Structured 7-stage security review workflow powered by AI")
    
    # Initialize workflow store
    workflow_store = WorkflowStore()
    
    # Input section
    col1, col2 = st.columns([2, 1])
    
    with col1:
        repo_url = st.text_input(
            "GitHub Repository URL",
            placeholder="https://github.com/username/repository"
        )
    
    with col2:
        review_type = st.selectbox(
            "Review Type",
            [
                "Input Validation",
                "Whitelisting Review",
                "Secrets Detection",
                "Authentication Review",
                "Authorization Review",
                "Dependency Security",
                "Logging & Monitoring",
                "Comprehensive Review"
            ]
        )
    
    if st.button("🚀 Start Security Review", type="primary", use_container_width=True):
        if not repo_url:
            st.error("Please enter a repository URL")
        else:
            # Create new workflow
            scan_id = str(uuid.uuid4())[:8]
            workflow = WorkflowManager(scan_id, repo_url, st.session_state.username)
            
            # Initialize workflow
            workflow.start()
            workflow_store.save_workflow(workflow)
            
            # Clone repository
            with st.spinner("Cloning repository..."):
                try:
                    repo_path = clone_repository(repo_url)
                    
                    if not repo_path or not repo_path.exists():
                        st.error("Failed to clone repository")
                        workflow.fail("Repository clone failed", ScanStage.REPOSITORY_DETAILS)
                        workflow_store.save_workflow(workflow)
                        return
                    
                    # Render progressive stages
                    all_data = {}
                    
                    # Stage 1: Repository Details
                    workflow.advance_stage(
                        ScanStage.REPOSITORY_DETAILS,
                        render_repository_details(workflow, repo_path)
                    )
                    workflow_store.save_workflow(workflow)
                    all_data["repository_details"] = workflow.stage_data[ScanStage.REPOSITORY_DETAILS.value]
                    
                    # Stage 2: Repository Analysis
                    workflow.advance_stage(
                        ScanStage.REPOSITORY_ANALYSIS,
                        render_repository_analysis(workflow, repo_path, review_type)
                    )
                    workflow_store.save_workflow(workflow)
                    all_data["repository_analysis"] = workflow.stage_data[ScanStage.REPOSITORY_ANALYSIS.value]
                    
                    # Stage 3: Relevant Files
                    workflow.advance_stage(
                        ScanStage.RELEVANT_FILES,
                        render_relevant_files(workflow, repo_path, review_type)
                    )
                    workflow_store.save_workflow(workflow)
                    all_data["relevant_files"] = workflow.stage_data[ScanStage.RELEVANT_FILES.value]
                    
                    # Stage 4: Relevant Snippets
                    workflow.advance_stage(
                        ScanStage.RELEVANT_SNIPPETS,
                        render_relevant_snippets(workflow, repo_path, review_type)
                    )
                    workflow_store.save_workflow(workflow)
                    all_data["relevant_snippets"] = workflow.stage_data[ScanStage.RELEVANT_SNIPPETS.value]
                    
                    # Stage 5: Security Findings
                    workflow.advance_stage(
                        ScanStage.SECURITY_FINDINGS,
                        render_security_findings(workflow, repo_path, review_type)
                    )
                    workflow_store.save_workflow(workflow)
                    all_data["findings"] = workflow.stage_data[ScanStage.SECURITY_FINDINGS.value]
                    
                    # Stage 6: AI Reasoning
                    workflow.advance_stage(
                        ScanStage.AI_REASONING,
                        render_ai_reasoning(workflow, repo_path, review_type, all_data["findings"])
                    )
                    workflow_store.save_workflow(workflow)
                    all_data["ai_reasoning"] = workflow.stage_data[ScanStage.AI_REASONING.value]
                    
                    # Stage 7: Final Report
                    workflow.advance_stage(
                        ScanStage.FINAL_REPORT,
                        render_final_report(workflow, repo_url, review_type, all_data)
                    )
                    workflow_store.save_workflow(workflow)
                    
                    st.balloons()
                    st.success("🎉 Security review completed successfully!")
                    
                except Exception as e:
                    st.error(f"Scan failed: {str(e)}")
                    workflow.fail(str(e), workflow.current_stage or ScanStage.REPOSITORY_DETAILS)
                    workflow_store.save_workflow(workflow)
    
    # Show recent workflows
    st.divider()
    st.subheader("📜 Recent Scans")
    
    recent_workflows = workflow_store.get_workflows_by_user(st.session_state.username)[-5:]
    
    if recent_workflows:
        for wf in reversed(recent_workflows):
            status_color = {
                "Draft": "gray",
                "Queued": "blue",
                "Running": "orange",
                "Completed": "green",
                "Failed": "red",
                "Cancelled": "gray"
            }.get(wf.status, "gray")
            
            with st.expander(
                f"{'✅' if wf.status == 'Completed' else '🔄' if wf.status == 'Running' else '❌' if wf.status == 'Failed' else '⏳'} "
                f"{wf.repository_url.split('/')[-1]} - {wf.status}"
            ):
                st.write(f"**Scan ID:** {wf.scan_id}")
                st.write(f"**Started:** {wf.started_at}")
                st.write(f"**Progress:** {wf.get_progress_percentage()}%")
                st.write(f"**Current Stage:** {wf.current_stage.value if wf.current_stage else 'N/A'}")


if __name__ == "__main__":
    main()
