"""
ReBIT AI SSDLC Review Platform - Streamlit Frontend
Single-file enterprise UI with Role-Based Access and 7-Stage Workflow.
"""

import streamlit as st
import sys
import os
from datetime import datetime

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from workflow_engine import (
    WorkflowManager, ReviewStatus, ReviewStage, 
    RelevantFile, CodeSnippet, AIFinding
)

# --- Page Configuration ---
st.set_page_config(
    page_title="ReBIT AI SSDLC Review Platform",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Custom CSS for Enterprise Look ---
st.markdown("""
<style>
    .main-header {font-size: 2.5rem; font-weight: 700; color: #1E88E5; margin-bottom: 1rem;}
    .sub-header {font-size: 1.2rem; color: #666; margin-bottom: 2rem;}
    .stage-card {background-color: #f9f9f9; padding: 1rem; border-radius: 8px; border-left: 5px solid #ccc; margin-bottom: 1rem;}
    .stage-active {border-left-color: #1E88E5; background-color: #e3f2fd;}
    .stage-done {border-left-color: #4CAF50; background-color: #e8f5e9;}
    .metric-box {background-color: white; padding: 1.5rem; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center;}
    .metric-value {font-size: 2rem; font-weight: bold; color: #1E88E5;}
    .metric-label {color: #666; font-size: 0.9rem;}
    .finding-critical {border-left: 4px solid #d32f2f; background-color: #ffebee;}
    .finding-high {border-left: 4px solid #f57c00; background-color: #fff3e0;}
    .finding-medium {border-left: 4px solid #fbc02d; background-color: #fffde7;}
    .code-snippet {background-color: #263238; color: #aed581; padding: 1rem; border-radius: 5px; font-family: monospace; overflow-x: auto;}
</style>
""", unsafe_allow_html=True)

# --- Session State Initialization ---
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'user_email' not in st.session_state:
    st.session_state.user_email = ""
if 'user_role' not in st.session_state:
    st.session_state.user_role = ""

# --- Authentication Mock ---
def login(email: str, role: str):
    st.session_state.logged_in = True
    st.session_state.user_email = email
    st.session_state.user_role = role
    st.rerun()

def logout():
    st.session_state.logged_in = False
    st.session_state.user_email = ""
    st.session_state.user_role = ""
    st.rerun()

# --- Login Page ---
if not st.session_state.logged_in:
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("<h1 style='text-align: center;'>🔒 ReBIT AI SSDLC</h1>", unsafe_allow_html=True)
        st.markdown("<p style='text-align: center;'>Enterprise Security Review Platform</p>", unsafe_allow_html=True)
        st.divider()
        
        with st.form("login_form"):
            email = st.text_input("Email", placeholder="developer@rebit.com")
            role = st.selectbox("Role", ["Developer", "Manager"])
            submitted = st.form_submit_button("Login", use_container_width=True)
            
            if submitted:
                if email:
                    login(email, role)
                else:
                    st.error("Please enter an email address.")
    st.stop()

# --- Main Application ---
st.sidebar.title(f"👤 {st.session_state.user_email}")
st.sidebar.subtitle(f"Role: **{st.session_state.user_role}**")
st.sidebar.divider()

# Role-Based Navigation
if st.session_state.user_role == "Developer":
    menu = st.sidebar.radio("Navigation", ["Dashboard", "New Scan", "My History", "Reports"])
else: # Manager
    menu = st.sidebar.radio("Navigation", ["Dashboard", "Review Queue", "Repository Explorer", "Analytics"])

st.sidebar.divider()
if st.sidebar.button("Logout"):
    logout()

# --- Helper Functions ---
def render_stage_indicator(current_stage: ReviewStage, progress: int):
    stages = list(ReviewStage)
    current_idx = stages.index(current_stage)
    
    cols = st.columns(len(stages))
    for i, stage in enumerate(stages):
        with cols[i]:
            if i < current_idx:
                st.success(f"✅ {stage.value}")
            elif i == current_idx:
                st.info(f"🔄 {stage.value}")
            else:
                st.write(f"⏳ {stage.value}")
    
    st.progress(progress / 100)

def render_finding_card(finding: AIFinding):
    severity_color = "finding-critical" if finding.severity == "CRITICAL" else \
                     "finding-high" if finding.severity == "HIGH" else "finding-medium"
    
    with st.container():
        st.markdown(f"""
        <div class="stage-card {severity_color}" style="padding: 1.5rem; border-radius: 8px; margin-bottom: 1.5rem;">
            <h3 style="margin-top:0;">{finding.severity}: {finding.title}</h3>
            <p><strong>Confidence:</strong> {finding.confidence_score}% | <strong>CWE:</strong> {finding.cwe}</p>
        </div>
        """, unsafe_allow_html=True)
        
        col1, col2 = st.columns([2, 1])
        with col1:
            st.markdown("**🧠 AI Reasoning**")
            st.info(f"**Why Vulnerable:** {finding.why_vulnerable}")
            st.warning(f"**Business Impact:** {finding.business_impact}")
            st.error(f"**Technical Impact:** {finding.technical_impact}")
            
            st.markdown("**🛡️ OWASP Mapping**")
            st.code(f"Top 10: {finding.owasp_top10}\nASVS: {finding.owasp_asvs}")
            
            st.markdown("**✅ Recommendation**")
            st.success(finding.recommendation)
            
        with col2:
            st.markdown("**📄 Code Snippet**")
            st.markdown(f"`{finding.snippet.file_path}` (Lines {finding.snippet.start_line}-{finding.snippet.end_line})")
            st.code(finding.snippet.code, language="python")

# --- Dashboard View ---
if menu == "Dashboard":
    st.markdown(f"<h1 class='main-header'>Welcome, {st.session_state.user_email.split('@')[0]}</h1>", unsafe_allow_html=True)
    st.markdown(f"<p class='sub-header'>Overview of your security review activities.</p>", unsafe_allow_html=True)
    
    # Fetch Data
    reviews = WorkflowManager.get_all_reviews(st.session_state.user_email, st.session_state.user_role)
    completed = [r for r in reviews if r.status == ReviewStatus.COMPLETED]
    pending = [r for r in reviews if r.status in [ReviewStatus.RUNNING, ReviewStatus.PENDING]]
    
    # Metrics
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(f"<div class='metric-box'><div class='metric-value'>{len(reviews)}</div><div class='metric-label'>Total Scans</div></div>", unsafe_allow_html=True)
    with m2:
        st.markdown(f"<div class='metric-box'><div class='metric-value'>{len(completed)}</div><div class='metric-label'>Completed</div></div>", unsafe_allow_html=True)
    with m3:
        risk_avg = sum(r.risk_score for r in completed) / len(completed) if completed else 0
        st.markdown(f"<div class='metric-box'><div class='metric-value'>{risk_avg:.1f}</div><div class='metric-label'>Avg Risk Score</div></div>", unsafe_allow_html=True)
    with m4:
        critical_count = sum(1 for r in completed for f in r.findings if f.severity == "CRITICAL")
        st.markdown(f"<div class='metric-box'><div class='metric-value'>{critical_count}</div><div class='metric-label'>Critical Findings</div></div>", unsafe_allow_html=True)
    
    st.divider()
    
    # Recent Activity
    st.subheader("Recent Reviews")
    if not reviews:
        st.info("No scans performed yet. Start a new scan!")
    else:
        for r in sorted(reviews, key=lambda x: x.updated_at, reverse=True)[:5]:
            c1, c2, c3, c4, c5 = st.columns([3, 2, 2, 2, 1])
            with c1:
                st.write(f"**{r.intelligence.name if r.intelligence else 'Processing...'}**")
                st.caption(r.repo_url)
            with c2:
                status_color = "🟢" if r.status == ReviewStatus.COMPLETED else "🟡" if r.status == ReviewStatus.RUNNING else "🔴"
                st.write(f"{status_color} {r.status.value}")
            with c3:
                st.write(f"Risk: **{r.risk_score}**")
            with c4:
                st.caption(r.updated_at.split('T')[0])
            with c5:
                if st.button("View", key=f"view_{r.id}"):
                    st.session_state.current_view_id = r.id
                    st.rerun()

# --- New Scan View (Developer Only) ---
elif menu == "New Scan":
    if st.session_state.user_role != "Developer":
        st.warning("Access Denied. Developers only.")
        st.stop()
        
    st.markdown(f"<h1 class='main-header'>Start New Security Review</h1>", unsafe_allow_html=True)
    
    with st.form("scan_form"):
        repo_url = st.text_input("Repository URL", placeholder="https://github.com/username/repo")
        review_types = st.multiselect("Review Types", ["Static Analysis", "Dependency Check", "Secrets Detection", "AI Reasoning"], default=["AI Reasoning"])
        start_btn = st.form_submit_button("Start Review", use_container_width=True, type="primary")
        
        if start_btn:
            if not repo_url:
                st.error("Please provide a repository URL.")
            else:
                # Initialize Session
                session = WorkflowManager.start_review(repo_url, st.session_state.user_email, review_types)
                st.session_state.current_scan_id = session.id
                st.rerun()

    # Active Scan Progress
    if 'current_scan_id' in st.session_state:
        session_id = st.session_state.current_scan_id
        # Refresh session data
        all_reviews = WorkflowManager.get_all_reviews(st.session_state.user_email, st.session_state.user_role)
        session = next((r for r in all_reviews if r.id == session_id), None)
        
        if session:
            st.divider()
            st.subheader("Scan Progress")
            render_stage_indicator(session.current_stage, session.progress_percent)
            
            # Dynamic Content based on Stage
            if session.intelligence:
                with st.expander("📊 Repository Intelligence", expanded=True):
                    c1, c2, c3 = st.columns(3)
                    c1.metric("Language", session.intelligence.primary_language)
                    c2.metric("Framework", session.intelligence.framework)
                    c3.metric("Files Scanned", session.intelligence.files_scanned)
                    st.code(", ".join(session.intelligence.dependencies), language="text")
            
            if session.relevant_files:
                with st.expander("📁 Relevant Files", expanded=True):
                    df_data = []
                    for f in session.relevant_files:
                        df_data.append({
                            "File": f.path,
                            "Relevance": f"{f.relevance_score}%",
                            "Reason": f.reason,
                            "Findings": f.findings_count
                        })
                    st.dataframe(df_data, use_container_width=True, hide_index=True)
            
            if session.findings:
                st.divider()
                st.subheader("🚨 AI Security Findings")
                for finding in session.findings:
                    render_finding_card(finding)
                
                # Final Report Generation
                if session.status == ReviewStatus.COMPLETED:
                    st.success("✅ Review Completed Successfully!")
                    st.markdown(f"**Executive Summary:** {session.executive_summary}")
                    
                    if st.button("Download PDF Report"):
                        st.toast("Report generated successfully! (Mock)")
                    
                    del st.session_state.current_scan_id

# --- My History ---
elif menu == "My History":
    st.markdown(f"<h1 class='main-header'>Scan History</h1>", unsafe_allow_html=True)
    reviews = WorkflowManager.get_all_reviews(st.session_state.user_email, st.session_state.user_role)
    
    if not reviews:
        st.info("No history available.")
    else:
        for r in reviews:
            with st.expander(f"{r.intelligence.name if r.intelligence else 'Unknown'} - {r.status.value}", expanded=False):
                st.write(f"**URL:** {r.repo_url}")
                st.write(f"**Date:** {r.created_at}")
                st.write(f"**Risk Score:** {r.risk_score}")
                if r.manager_feedback:
                    st.info(f"**Manager Feedback:** {r.manager_feedback}")

# --- Manager: Review Queue ---
elif menu == "Review Queue":
    if st.session_state.user_role != "Manager":
        st.warning("Access Denied. Managers only.")
        st.stop()
        
    st.markdown(f"<h1 class='main-header'>Manager Review Queue</h1>", unsafe_allow_html=True)
    reviews = WorkflowManager.get_all_reviews(st.session_state.user_email, st.session_state.user_role)
    pending_reviews = [r for r in reviews if r.status == ReviewStatus.COMPLETED and not r.manager_feedback]
    
    if not pending_reviews:
        st.success("✅ All reviews processed.")
    else:
        for r in pending_reviews:
            st.divider()
            c1, c2 = st.columns([3, 1])
            with c1:
                st.markdown(f"**{r.intelligence.name}** (Risk: {r.risk_score})")
                st.caption(f"By: {r.user_email}")
            with c2:
                if st.button("Approve", key=f"app_{r.id}"):
                    WorkflowManager.approve_review(r.id, "Approved by Manager.")
                    st.rerun()
                if st.button("Reject", key=f"rej_{r.id}"):
                    WorkflowManager.reject_review(r.id, "Needs rework.")
                    st.rerun()
            
            # Show summary details for quick decision
            st.write(f"**Summary:** {r.executive_summary[:150]}...")
            st.write(f"**Critical Findings:** {sum(1 for f in r.findings if f.severity == 'CRITICAL')}")

# --- Placeholder Pages ---
else:
    st.markdown(f"<h1 class='main-header'>{menu}</h1>", unsafe_allow_html=True)
    st.info("This module is under development for the demo.")
