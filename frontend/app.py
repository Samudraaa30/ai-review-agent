import streamlit as st
import sys
import os
import threading
import time
import pandas as pd
import json
from datetime import datetime

# Add backend to path
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from backend.workflow_engine import (
    WorkflowManager,
    ReviewStatus,
    ReviewStage,
    RelevantFile,
    CodeSnippet,
    AIFinding,
    review_store,
)

# --- Page Configuration ---
st.set_page_config(
    page_title="ReBIT AI SSDLC Review Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Background Thread Manager for Scans ---
if 'running_scans' not in st.session_state:
    st.session_state.running_scans = {}
if 'finding_statuses' not in st.session_state:
    st.session_state.finding_statuses = {} # Maps finding_id -> status (Open, In Review, Resolved, False Positive)

def run_pipeline_async(session_id: str):
    """Executes the pipeline inside a background thread so the UI remains highly responsive."""
    try:
        WorkflowManager.execute_pipeline(session_id)
    except Exception as e:
        if session_id in review_store:
            review_store[session_id].status = ReviewStatus.FAILED
            review_store[session_id].error_message = str(e)
    finally:
        if session_id in st.session_state.running_scans:
            st.session_state.running_scans.pop(session_id, None)

# --- Styling & CSS Injector ---
st.markdown("""
<style>
    /* Global styles and typography */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
    
    /* Header & Accents */
    .main-header { font-size: 2.25rem; font-weight: 700; color: #0F172A; margin-bottom: 0.25rem; letter-spacing: -0.025em; }
    .sub-header { font-size: 1.05rem; color: #475569; margin-bottom: 1.75rem; }
    .section-header { font-size: 1.5rem; font-weight: 600; color: #1E293B; margin-top: 1.5rem; margin-bottom: 1rem; border-bottom: 1px solid #E2E8F0; padding-bottom: 0.5rem; }
    
    /* Severity Badges */
    .badge { padding: 4px 10px; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; display: inline-block; }
    .badge-critical { background-color: #FEE2E2; color: #991B1B; border: 1px solid #FCA5A5; }
    .badge-high { background-color: #FFEDD5; color: #9A3412; border: 1px solid #FDBA74; }
    .badge-medium { background-color: #FEF9C3; color: #713F12; border: 1px solid #FDE047; }
    .badge-low { background-color: #E0F2FE; color: #075985; border: 1px solid #7DD3FC; }
    
    /* Status Badges */
    .stat-badge { padding: 4px 10px; border-radius: 6px; font-size: 0.75rem; font-weight: 600; display: inline-block; }
    .stat-queued { background-color: #F1F5F9; color: #475569; border: 1px solid #CBD5E1; }
    .stat-running { background-color: #DBEAFE; color: #1E40AF; border: 1px solid #93C5FD; }
    .stat-approved { background-color: #DCFCE7; color: #166534; border: 1px solid #86EFAC; }
    .stat-rejected { background-color: #FEE2E2; color: #991B1B; border: 1px solid #FCA5A5; }
    .stat-failed { background-color: #1E293B; color: #F8FAFC; border: 1px solid #475569; }
    
    /* Stepper Component */
    .stepper-container { display: flex; justify-content: space-between; align-items: center; background-color: #F8FAFC; padding: 1.25rem; border-radius: 12px; border: 1px solid #E2E8F0; margin-bottom: 1.5rem; }
    .stepper-step { display: flex; flex-direction: column; align-items: center; flex: 1; position: relative; text-align: center; z-index: 1; }
    .stepper-step:not(:last-child)::after { content: ''; position: absolute; top: 24px; left: 50%; width: 100%; height: 2px; background-color: #E2E8F0; z-index: -1; }
    .stepper-step.completed:not(:last-child)::after { background-color: #10B981; }
    .stepper-icon { width: 48px; height: 48px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; background-color: #F1F5F9; color: #94A3B8; border: 2px solid #E2E8F0; transition: all 0.3s ease; }
    .stepper-step.completed .stepper-icon { background-color: #10B981; color: white; border-color: #10B981; }
    .stepper-step.active .stepper-icon { background-color: #3B82F6; color: white; border-color: #3B82F6; box-shadow: 0 0 0 4px #DBEAFE; }
    .stepper-label { margin-top: 0.5rem; font-size: 0.75rem; font-weight: 500; color: #475569; max-width: 120px; }
    .stepper-step.active .stepper-label { color: #3B82F6; font-weight: 600; }
    
    /* Interactive Dashboard Metrics */
    .metric-card { background: white; border: 1px solid #E2E8F0; border-radius: 12px; padding: 1.25rem; box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.05); display: flex; flex-direction: column; gap: 0.25rem; transition: transform 0.2s ease; }
    .metric-card:hover { transform: translateY(-2px); box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); }
    .metric-card-val { font-size: 1.8rem; font-weight: 700; color: #0F172A; }
    .metric-card-lbl { font-size: 0.85rem; color: #64748B; font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em; }
    
    /* Document/Expander styling */
    .stExpander { border-radius: 10px !important; border: 1px solid #E2E8F0 !important; box-shadow: 0 1px 2px 0 rgba(0,0,0,0.03) !important; background: white !important; margin-bottom: 0.75rem !important; }
    
    /* Finding Cards */
    .finding-card { background: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 8px; padding: 1.25rem; margin-bottom: 1rem; border-left-width: 4px; box-shadow: 0 1px 2px 0 rgba(0,0,0,0.05); }
    .finding-card.CRITICAL { border-left-color: #DC2626; }
    .finding-card.HIGH { border-left-color: #EA580C; }
    .finding-card.MEDIUM { border-left-color: #CA8A04; }
    .finding-card.LOW { border-left-color: #0284C7; }
</style>
""", unsafe_allow_html=True)

# --- Session State Initialization ---
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'user_email' not in st.session_state:
    st.session_state.user_email = ""
if 'user_role' not in st.session_state:
    st.session_state.user_role = ""
if 'current_view_id' not in st.session_state:
    st.session_state.current_view_id = None

# --- Authentication Logic ---
def login(email: str, role: str):
    st.session_state.logged_in = True
    st.session_state.user_email = email
    st.session_state.user_role = role
    st.session_state.current_view_id = None
    st.rerun()

def logout():
    st.session_state.logged_in = False
    st.session_state.user_email = ""
    st.session_state.user_role = ""
    st.session_state.current_view_id = None
    st.session_state.running_scans = {}
    st.rerun()

# --- Login Page ---
if not st.session_state.logged_in:
    col1, col2, col3 = st.columns([1, 1.8, 1])
    with col2:
        st.write("")
        st.write("")
        st.markdown("""
        <div style="background-color: white; padding: 2.5rem; border-radius: 16px; border: 1px solid #E2E8F0; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);">
            <div style="text-align: center; margin-bottom: 2rem;">
                <h1 style="font-size: 2rem; color: #1E3A8A; font-weight: 800; margin-bottom:0.25rem;">🔒 ReBIT AI SSDLC</h1>
                <p style="color: #64748B; font-size: 0.95rem;">Reserve Bank Information Technology Pvt. Ltd.</p>
                <div style="height: 3px; width: 60px; background-color: #3B82F6; margin: 1rem auto;"></div>
            </div>
        """, unsafe_allow_html=True)
        
        with st.form("login_form"):
            st.markdown("<p style='font-weight: 500; margin-bottom:0.25rem; color:#334155;'>Enterprise Email Address</p>", unsafe_allow_html=True)
            email = st.text_input("Email", placeholder="username@rebit.org.in", label_visibility="collapsed")
            
            st.markdown("<p style='font-weight: 500; margin-top:1rem; margin-bottom:0.25rem; color:#334155;'>Security Role Context</p>", unsafe_allow_html=True)
            role = st.selectbox("Role", ["Developer", "Manager"], label_visibility="collapsed")
            
            st.write("")
            submitted = st.form_submit_button("Authenticate into Platform", use_container_width=True, type="primary")
            
            if submitted:
                if email:
                    login(email, role)
                else:
                    st.error("Authentication rejected. Enterprise email address is required.")
        st.markdown("</div>", unsafe_allow_html=True)
    st.stop()

# --- Main Page Layout ---
st.sidebar.markdown(f"""
<div style="background-color: #0F172A; padding: 1.25rem; border-radius: 10px; margin-bottom: 1.5rem; border: 1px solid #1E293B;">
    <p style="color: #94A3B8; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom:0.25rem;">Authenticated User</p>
    <p style="color: white; font-weight: 600; font-size: 0.95rem; word-break: break-all; margin-bottom:0.5rem;">👤 {st.session_state.user_email}</p>
    <div style="display:inline-block; background-color:#1E293B; border: 1px solid #334155; padding: 2px 10px; border-radius: 4px;">
        <span style="color: #38BDF8; font-weight: 700; font-size: 0.75rem;">🛡️ {st.session_state.user_role}</span>
    </div>
</div>
""", unsafe_allow_html=True)

# Navigation Menu
if st.session_state.user_role == "Developer":
    menu = st.sidebar.radio("Platform Navigation", ["Dashboard", "New Scan Engine", "Repository Explorer", "Compare Scans", "Scan History", "Report Center"])
else:  # Manager
    menu = st.sidebar.radio("Platform Navigation", ["Dashboard", "Manager Review Queue", "Repository Explorer", "Compare Scans", "Scan History", "Report Center"])

st.sidebar.markdown("---")
if st.sidebar.button("System Logout", use_container_width=True, type="secondary"):
    logout()

# --- Shared UI Helpers ---
def render_stage_stepper(current_stage: ReviewStage, status: ReviewStatus):

    stages = list(ReviewStage)
    current_idx = stages.index(current_stage)

    cols = st.columns(len(stages))

    for i, (col, stage) in enumerate(zip(cols, stages)):

        completed = (
            i < current_idx or
            status in [
                ReviewStatus.COMPLETED,
                ReviewStatus.APPROVED,
                ReviewStatus.REJECTED
            ]
        )

        active = (
            i == current_idx and
            status == ReviewStatus.RUNNING
        )

        if completed:
            icon = "✅"
        elif active:
            icon = "🔄"
        else:
            icon = str(i + 1)

        with col:
            st.markdown(
                f"""
                <div style="text-align:center;">
                    <div style="
                        width:48px;
                        height:48px;
                        border-radius:50%;
                        background:{'#10B981' if completed else '#3B82F6' if active else '#CBD5E1'};
                        color:white;
                        display:flex;
                        align-items:center;
                        justify-content:center;
                        margin:auto;
                        font-weight:bold;
                    ">
                        {icon}
                    </div>

                    <div style="margin-top:8px;font-size:12px;">
                        {stage.value}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

def get_severity_badge(severity: str) -> str:
    sev = severity.upper()
    if "CRITICAL" in sev: return f'<span class="badge badge-critical">Critical</span>'
    elif "HIGH" in sev: return f'<span class="badge badge-high">High</span>'
    elif "MEDIUM" in sev: return f'<span class="badge badge-medium">Medium</span>'
    else: return f'<span class="badge badge-low">Low</span>'

def get_status_badge(status: ReviewStatus, stage: ReviewStage) -> str:
    if status == ReviewStatus.RUNNING:
        if stage in [ReviewStage.INIT, ReviewStage.FILES, ReviewStage.FUNCTIONS, ReviewStage.SNIPPETS]:
            return '<span class="stat-badge stat-running">Repository Analysis</span>'
        elif stage == ReviewStage.AI_REASONING:
            return '<span class="stat-badge stat-running">AI Reviewing</span>'
        else:
            return '<span class="stat-badge stat-running">Running</span>'
    elif status == ReviewStatus.COMPLETED:
        return '<span class="stat-badge stat-queued">Awaiting Manager</span>'
    elif status == ReviewStatus.APPROVED:
        return '<span class="stat-badge stat-approved">Approved</span>'
    elif status == ReviewStatus.REJECTED:
        return '<span class="stat-badge stat-rejected">Rejected</span>'
    elif status == ReviewStatus.FAILED:
        return '<span class="stat-badge stat-failed">Failed</span>'
    return '<span class="stat-badge stat-queued">Queued</span>'

def render_finding_traceability_card(f: AIFinding, session):
    status_key = f"btn_{f.id}_{id(f)}"
    current_f_status = st.session_state.finding_statuses.get(f.id, "Open")
    
    st.markdown(f"""
    <div class="finding-card {f.severity.upper()}">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 10px;">
            <div style="font-size: 1.1rem; font-weight: 700; color: #1E293B;">{f.id}: {f.title}</div>
            <div style="display:flex; gap: 8px;">
                <span class="stat-badge stat-queued">{current_f_status}</span>
                {get_severity_badge(f.severity)}
            </div>
        </div>
        <div style="font-size: 0.9rem; color: #475569; margin-bottom: 10px;">
            <strong>Repo:</strong> {session.repo_url} | <strong>File:</strong> <code>{f.snippet.file_path}</code>
        </div>
    """, unsafe_allow_html=True)
    
    with st.expander("🔍 View Complete Vulnerability Traceability & Details"):
        tab1, tab2, tab3 = st.tabs(["Analysis & Impact", "Code Snippet & Remediation", "Status & Management"])
        
        with tab1:
            st.markdown(f"**Description:** {f.description}")
            st.markdown(f"**AI Root Cause Analysis:** {f.why_vulnerable}")
            st.markdown("---")
            c1, c2 = st.columns(2)
            c1.markdown(f"🔴 **Technical Impact:** {f.technical_impact}")
            c2.markdown(f"💼 **Business Impact:** {f.business_impact}")
            st.markdown("---")
            st.markdown(f"**Standards Mapping:** OWASP Top 10: `{f.owasp_top10}` | ASVS: `{f.owasp_asvs}` | CWE: `{f.cwe}`")
            st.markdown(f"**AI Confidence Score:** {f.confidence_score}%")
            
        with tab2:
            st.markdown(f"**Location:** Function `{f.snippet.function_name}()` | Lines: {f.snippet.start_line} - {f.snippet.end_line}")
            st.code(f.snippet.code, language="python")
            st.markdown("**🛡️ Recommendation:**")
            st.success(f.recommendation)
            st.markdown(f"**Evidence Trace:** {f.evidence}")
            
        with tab3:
            st.markdown("Update the status of this finding across the Enterprise SSDLC registry.")
            new_status = st.selectbox(
              "Finding Status",
              ["Open", "In Review", "Resolved", "False Positive"],
              index=["Open", "In Review", "Resolved", "False Positive"].index(current_f_status),
              key=f"sel_{f.id}_{id(f)}"
            )
            if new_status != current_f_status:
                st.session_state.finding_statuses[f.id] = new_status
                st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)


# --- PAGE: Dashboard ---
if menu == "Dashboard":
    st.markdown("<h1 class='main-header'>🏢 Enterprise Security Intelligence</h1>", unsafe_allow_html=True)
    st.markdown("<p class='sub-header'>Global view of secure software development lifecycle metrics.</p>", unsafe_allow_html=True)
    
    reviews = WorkflowManager.get_all_reviews(st.session_state.user_email, st.session_state.user_role)
    completed = [r for r in reviews if r.status in [ReviewStatus.COMPLETED, ReviewStatus.APPROVED, ReviewStatus.REJECTED]]
    pending = [r for r in reviews if r.status in [ReviewStatus.RUNNING, ReviewStatus.PENDING]]
    
    # KPIs
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(f'<div class="metric-card"><span class="metric-card-lbl">Total Reviews</span><span class="metric-card-val">{len(reviews)}</span></div>', unsafe_allow_html=True)
    with m2:
        st.markdown(f'<div class="metric-card"><span class="metric-card-lbl">Completed Scans</span><span class="metric-card-val">{len(completed)}</span></div>', unsafe_allow_html=True)
    with m3:
        avg_risk = sum(r.risk_score for r in completed) / len(completed) if completed else 0
        st.markdown(f'<div class="metric-card"><span class="metric-card-lbl">Avg Risk Score</span><span class="metric-card-val" style="color: {"#DC2626" if avg_risk > 50 else "#0F172A"};">{avg_risk:.1f}</span></div>', unsafe_allow_html=True)
    with m4:
        avg_dur = sum(r.intelligence.scan_duration for r in completed if r.intelligence) / len(completed) if completed else 0
        st.markdown(f'<div class="metric-card"><span class="metric-card-lbl">Avg Scan Time</span><span class="metric-card-val">{avg_dur:.1f}s</span></div>', unsafe_allow_html=True)
        
    st.write("")
    
    if not completed:
        st.info("No completed scans available to generate enterprise charts. Initiate a new scan engine run.")
    else:
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("<h3 class='section-header'>Risk Score Distribution</h3>", unsafe_allow_html=True)
            hist_df = pd.DataFrame([r.risk_score for r in completed], columns=["Risk Score"])
            st.bar_chart(hist_df["Risk Score"].value_counts().sort_index())
            
            st.markdown("<h3 class='section-header'>Top Target Repositories</h3>", unsafe_allow_html=True)
            repo_df = pd.DataFrame([r.repo_url.split('/')[-1] for r in completed], columns=["Repository"])
            st.bar_chart(repo_df["Repository"].value_counts())
            
        with c2:
            st.markdown("<h3 class='section-header'>Reviews Over Time</h3>", unsafe_allow_html=True)
            time_df = pd.DataFrame([r.created_at[:10] for r in completed], columns=["Date"])
            st.line_chart(time_df["Date"].value_counts().sort_index())

            st.markdown("<h3 class='section-header'>Finding Severity Distribution</h3>", unsafe_allow_html=True)
            sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for r in completed:
                for f in r.findings:
                    s = f.severity.upper()
                    if s in sev_counts: sev_counts[s] += 1
            st.bar_chart(pd.DataFrame([sev_counts]).T)

    st.markdown("<h3 class='section-header'>Latest Platform Activity</h3>", unsafe_allow_html=True)
    if not reviews:
        st.write("No activity recorded.")
    else:
        for r in sorted(reviews, key=lambda x: x.updated_at, reverse=True)[:5]:
            repo_name = r.intelligence.name if r.intelligence else r.repo_url.split('/')[-1]
            st.markdown(f"""
            <div style="background: white; border: 1px solid #E2E8F0; padding: 1rem; border-radius: 8px; margin-bottom: 0.5rem; display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <strong style="font-size: 1.1rem;">{repo_name}</strong> <span style="color: #64748B; font-size: 0.85rem; margin-left: 10px;">{r.updated_at.replace('T', ' ')[:16]}</span><br/>
                    <span style="font-size: 0.85rem; color: #475569;">Developer: {r.user_email} | Types: {', '.join(r.review_types)}</span>
                </div>
                <div style="text-align: right;">
                    {get_status_badge(r.status, r.current_stage)}<br/>
                    <strong style="font-size: 0.9rem;">Risk: {r.risk_score}/100</strong>
                </div>
            </div>
            """, unsafe_allow_html=True)

# --- PAGE: New Scan Engine ---
elif menu == "New Scan Engine":
    if st.session_state.user_role != "Developer":
        st.warning("Access Denied. Developers only.")
        st.stop()
        
    st.markdown("<h1 class='main-header'>🚀 Pipeline Engine Initiation</h1>", unsafe_allow_html=True)
    st.markdown("<p class='sub-header'>Progressive 7-stage automated assessment for target source repositories.</p>", unsafe_allow_html=True)
    
    with st.form("new_repo_scan_form"):
        repo_url = st.text_input("Git Repository URL", placeholder="https://github.com/rebit-cyber/internal-service")
        c1, c2 = st.columns(2)
        with c1:
            review_types = st.multiselect("Security Review Labels",
    [
        "Input Validation",
        "Whitelisting",
        "Secrets Detection",
        "Authentication Review",
        "Authorization Review",
        "Dependency Security",
        "Logging & Monitoring"
    ],
    default=[
        "Input Validation",
        "Secrets Detection"
    ])
        with c2:
            st.text_input("Developer Context (Auto)", value=st.session_state.user_email, disabled=True)
            
        submit_scan = st.form_submit_button("Initiate Security Scan Engine", use_container_width=True, type="primary")
        
        if submit_scan:
            if not repo_url:
                st.error("Submission rejected. Please target a valid git repository URL.")
            else:
                session = WorkflowManager.start_review(repo_url, st.session_state.user_email, review_types)
                st.session_state.current_scan_id = session.id
                scan_thread = threading.Thread(target=run_pipeline_async, args=(session.id,))
                st.session_state.running_scans[session.id] = scan_thread
                scan_thread.start()
                st.rerun()

    # --- Progressive Engine View ---
    if 'current_scan_id' in st.session_state and st.session_state.current_scan_id:
        s_id = st.session_state.current_scan_id
        session = review_store.get(s_id)
        
        if session:
            st.markdown("---")
            st.markdown(f"### ⚡ Active Pipeline Profile: `{session.id}`")
            
            # Top Controls & Stepper
            c_p1, c_p2 = st.columns([5, 1])
            with c_p1: render_stage_stepper(session.current_stage, session.status)
            with c_p2:
                if s_id in st.session_state.running_scans:
                    st.markdown("<div style='margin-top: 1.5rem;'></div>", unsafe_allow_html=True)
                    if st.button("🔄 Check Engine State", type="primary", use_container_width=True): st.rerun()
                    
            if session.status == ReviewStatus.RUNNING:
                st.info(f"🔄 Engine Processing: **{session.current_stage.value}**... Synthesizing outputs.")
            elif session.status == ReviewStatus.FAILED:
                st.error(f"❌ Core processing crashed: {session.error_message}")
                
            # Enterprise Metadata Panel (Req 7)
            with st.expander("⚙️ Enterprise Pipeline Metadata Profile", expanded=False):
                st.markdown("Detailed diagnostic configuration mapped to this specific run execution.")
                col1, col2, col3, col4 = st.columns(4)
                col1.markdown(f"**Repository:** {session.repo_url.split('/')[-1]}\n\n**Started:** {session.created_at[:16]}")
                col2.markdown(f"**Developer:** {session.user_email}\n\n**Status:** {session.status.value}")
                col3.markdown(f"**Risk Score:** {session.risk_score}\n\n**Plugins:** {len(session.review_types)}")
                col4.markdown(f"**Progress:** {session.progress_percent}%\n\n**Total Findings:** {len(session.findings)}")
                if session.intelligence:
                    st.markdown("---")
                    col1.markdown(f"**Language:** {session.intelligence.primary_language}\n\n**Files Scanned:** {session.intelligence.files_scanned}")
                    col2.markdown(f"**Framework:** {session.intelligence.framework}\n\n**Duration:** {session.intelligence.scan_duration}s")
                    col3.markdown(f"**Relevant Files:** {session.intelligence.relevant_files_count}")

            # Progressive Unlock Containers (Req 1)
            stages_list = list(ReviewStage)
            curr_idx = stages_list.index(session.current_stage) if session.current_stage in stages_list else 0
            is_done = session.status in [ReviewStatus.COMPLETED, ReviewStatus.APPROVED, ReviewStatus.REJECTED]

            # Stage 1 Container
            stage1_unlocked = curr_idx >= 0 or is_done
            if stage1_unlocked:
                with st.container():
                    st.markdown("<div style='border-left: 4px solid #3B82F6; padding-left: 1rem; margin-bottom: 1rem;'>", unsafe_allow_html=True)
                    st.subheader("1. Repository Intelligence")
                    if session.intelligence:
                        i1, i2, i3, i4 = st.columns(4)
                        i1.metric("Language", session.intelligence.primary_language)
                        i2.metric("Framework", session.intelligence.framework)
                        i3.metric("Files Cataloged", session.intelligence.files_scanned)
                        i4.metric("Dependencies", len(session.intelligence.dependencies))
                        st.code("\n".join(session.intelligence.dependencies) if session.intelligence.dependencies else "None identified", language="text")
                    else:
                        st.spinner("Mapping dependency trees and catalog structures...")
                    st.markdown("</div>", unsafe_allow_html=True)

            # Stage 2,3,4 Container
            stage2_unlocked = curr_idx >= 1 or is_done
            if stage2_unlocked:
                with st.container():
                    st.markdown("<div style='border-left: 4px solid #10B981; padding-left: 1rem; margin-bottom: 1rem;'>", unsafe_allow_html=True)
                    st.subheader("2. Qwen Selected Relevance Matrix (Files & Snippets)")
                    if session.relevant_files:
                        df = pd.DataFrame([{"File": f.path, "AI Relevance": f.relevance_score, "Reason": f.reason} for f in session.relevant_files])
                        st.dataframe(df, use_container_width=True, hide_index=True)
                    else:
                        st.spinner("AI Agent identifying vulnerable code domains...")
                    st.markdown("</div>", unsafe_allow_html=True)

            # Stage 5 & 6 Container
            stage5_unlocked = curr_idx >= 4 or is_done
            if stage5_unlocked:
                with st.container():
                    st.markdown("<div style='border-left: 4px solid #F59E0B; padding-left: 1rem; margin-bottom: 1rem;'>", unsafe_allow_html=True)
                    st.subheader("3. Integrated Findings & Qwen AI Reasoning")
                    if session.findings:
                        st.success(f"Discovered and mapped {len(session.findings)} vulnerabilities.")
                        
                        # Filtering Component (Req 4)
                        st.markdown("##### Dynamic Filters")
                        f1, f2, f3, f4 = st.columns(4)
                        f_sev = f1.multiselect("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH"])
                        f_stat = f2.multiselect("Finding Status", ["Open", "In Review", "Resolved", "False Positive"], default=["Open", "In Review"])
                        f_type = f3.text_input("Vuln Type / Title")
                        f_file = f4.text_input("File Path")
                        
                        filtered_f = []
                        for f in session.findings:
                            f_curr_status = st.session_state.finding_statuses.get(f.id, "Open")
                            if (f.severity.upper() in f_sev) and (f_curr_status in f_stat):
                                if (not f_type) or (f_type.lower() in f.title.lower()):
                                    if (not f_file) or (f_file.lower() in f.snippet.file_path.lower()):
                                        filtered_f.append(f)
                                        
                        for f in filtered_f:
                            render_finding_traceability_card(f, session)
                    else:
                        st.spinner("Aggregating AST rules and passing context vectors to Qwen AI...")
                    st.markdown("</div>", unsafe_allow_html=True)

            # Stage 7 Container
            stage7_unlocked = curr_idx >= 6 or is_done
            if stage7_unlocked:
                with st.container():
                    st.markdown("<div style='border-left: 4px solid #8B5CF6; padding-left: 1rem; margin-bottom: 1rem;'>", unsafe_allow_html=True)
                    st.subheader("4. Executive Reporting Module")
                    if session.status == ReviewStatus.COMPLETED:
                        st.metric("Final Computed Risk Index", f"{session.risk_score} / 100")
                        st.info(session.executive_summary)
                    else:
                        st.spinner("Drafting executive summaries...")
                    st.markdown("</div>", unsafe_allow_html=True)

# --- PAGE: Repository Explorer ---
elif menu == "Repository Explorer":
    st.markdown("<h1 class='main-header'>🌲 Deep Repository Explorer</h1>", unsafe_allow_html=True)
    st.markdown("<p class='sub-header'>Hierarchical inspection of scanned repositories, mapped directly to AI snippet deductions.</p>", unsafe_allow_html=True)
    
    reviews = [r for r in WorkflowManager.get_all_reviews(st.session_state.user_email, st.session_state.user_role) if r.status in [ReviewStatus.COMPLETED, ReviewStatus.APPROVED, ReviewStatus.REJECTED]]
    
    if not reviews:
        st.info("No completed scans available for exploration.")
    else:
        # Selector
        repo_options = {f"{r.repo_url.split('/')[-1]} [{r.created_at[:16]}]": r for r in reviews}
        sel_repo_key = st.selectbox("Select Target Enterprise Repository Snapshot:", list(repo_options.keys()))
        session = repo_options[sel_repo_key]
        
        st.markdown("---")
        
        col_tree, col_view = st.columns([1, 2])
        
        with col_tree:
            st.markdown("<h3 class='section-header'>Hierarchy View</h3>", unsafe_allow_html=True)
            if not session.relevant_files:
                st.write("No relevant files documented.")
            else:
                sel_file = st.selectbox("📁 Relevant Files", [f.path for f in session.relevant_files])
                
                # Filter snippets by file
                file_snippets = [s for s in session.snippets if s.file_path == sel_file]
                if file_snippets:
                    sel_func = st.selectbox("⚙️ Functions Exposed", list(set([s.function_name for s in file_snippets])))
                    
                    # Filter further by function
                    func_snippets = [s for s in file_snippets if s.function_name == sel_func]
                    sel_snip_idx = st.selectbox("📄 Code Snippets", range(len(func_snippets)), format_func=lambda i: f"Lines: {func_snippets[i].start_line} - {func_snippets[i].end_line}")
                    selected_snippet = func_snippets[sel_snip_idx]
                else:
                    st.write("No specific function boundaries isolated.")
                    selected_snippet = None
                    
        with col_view:
            st.markdown("<h3 class='section-header'>Inspector View</h3>", unsafe_allow_html=True)
            if selected_snippet:
                st.code(selected_snippet.code, language="python")
                
                # Match findings to this exact snippet
                linked_findings = [f for f in session.findings if f.snippet.file_path == selected_snippet.file_path and f.snippet.start_line == selected_snippet.start_line]
                
                if linked_findings:
                    st.markdown("#### 🚨 Linked Security Findings")
                    for f in linked_findings:
                        render_finding_traceability_card(f, session)
                else:
                    st.success("No critical AI findings bound directly to this exact snippet parameter line range.")
            else:
                st.info("Select a file and function block on the left tree array to inspect raw AST code parameters.")

# --- PAGE: Compare Scans ---
elif menu == "Compare Scans":
    st.markdown("<h1 class='main-header'>⚖️ Compare Pipeline Scans</h1>", unsafe_allow_html=True)
    st.markdown("<p class='sub-header'>Evaluate Risk Deltas and posture shifts between two distinct snapshot records.</p>", unsafe_allow_html=True)

    reviews = [r for r in WorkflowManager.get_all_reviews(st.session_state.user_email, st.session_state.user_role) if r.status in [ReviewStatus.COMPLETED, ReviewStatus.APPROVED, ReviewStatus.REJECTED]]
    
    if len(reviews) < 2:
        st.info("Insufficient completed scans for comparison delta analysis. Run at least 2 reviews.")
    else:
        options = {f"{r.repo_url.split('/')[-1]} [{r.created_at[:16]}]": r for r in reviews}
        
        c1, c2 = st.columns(2)
        with c1: scan_a_key = st.selectbox("Baseline Profile (A)", list(options.keys()))
        with c2: scan_b_key = st.selectbox("Target Profile (B)", list(options.keys()), index=1)
        
        scan_a = options[scan_a_key]
        scan_b = options[scan_b_key]
        
        st.markdown("<h3 class='section-header'>Security Posture Delta Matrix</h3>", unsafe_allow_html=True)
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Risk Score Index", scan_b.risk_score, delta=scan_b.risk_score - scan_a.risk_score, delta_color="inverse")
        m2.metric("Critical Findings", sum(1 for f in scan_b.findings if f.severity=="CRITICAL"), delta=sum(1 for f in scan_b.findings if f.severity=="CRITICAL") - sum(1 for f in scan_a.findings if f.severity=="CRITICAL"), delta_color="inverse")
        m3.metric("Relevant Target Files", len(scan_b.relevant_files), delta=len(scan_b.relevant_files) - len(scan_a.relevant_files))
        
        dur_b = scan_b.intelligence.scan_duration if scan_b.intelligence else 0
        dur_a = scan_a.intelligence.scan_duration if scan_a.intelligence else 0
        m4.metric("Scan Pipeline Duration", f"{dur_b}s", delta=f"{round(dur_b - dur_a, 2)}s", delta_color="inverse")
        
        st.markdown("<h3 class='section-header'>Target Assessment Breakdown</h3>", unsafe_allow_html=True)
        t_col1, t_col2 = st.columns(2)
        with t_col1:
            st.markdown(f"**Baseline Exec Summary:**\n\n{scan_a.executive_summary}")
        with t_col2:
            st.markdown(f"**Target Exec Summary:**\n\n{scan_b.executive_summary}")

# --- PAGE: Manager Review Queue ---
elif menu == "Manager Review Queue":
    if st.session_state.user_role != "Manager":
        st.warning("Access Denied. Executive Managers only.")
        st.stop()
        
    st.markdown("<h1 class='main-header'>📥 Compliance Endorsement Queue</h1>", unsafe_allow_html=True)
    st.markdown("<p class='sub-header'>Review and strictly endorse pipeline states of pending deployment blocks.</p>", unsafe_allow_html=True)
    
    reviews = WorkflowManager.get_all_reviews(st.session_state.user_email, st.session_state.user_role)
    pending_queue = [r for r in reviews if r.status == ReviewStatus.COMPLETED]
    
    # Sorting (Req 9)
    sort_choice = st.radio("Sort Priority By:", ["Highest Risk", "Newest", "Oldest"], horizontal=True)
    if sort_choice == "Highest Risk": pending_queue.sort(key=lambda x: x.risk_score, reverse=True)
    elif sort_choice == "Newest": pending_queue.sort(key=lambda x: x.created_at, reverse=True)
    else: pending_queue.sort(key=lambda x: x.created_at)
    
    if not pending_queue:
        st.success("✅ Excellent! No reviews waiting in your compliance queue.")
    else:
        st.markdown(f"**{len(pending_queue)}** audits pending governance sign-off.")
        st.markdown("---")
        
        # Professional Table Layout via custom columns
        col_h1, col_h2, col_h3, col_h4, col_h5, col_h6 = st.columns([2, 2, 1, 1, 1, 2])
        col_h1.markdown("**Repository**")
        col_h2.markdown("**Developer / Date**")
        col_h3.markdown("**Risk / Criticals**")
        col_h4.markdown("**Duration**")
        col_h5.markdown("**Status**")
        col_h6.markdown("**Actions**")
        st.markdown("<hr style='margin-top:0.5rem; margin-bottom:0.5rem;'/>", unsafe_allow_html=True)
        
        for r in pending_queue:
            repo_name = r.repo_url.split('/')[-1]
            c_h1, c_h2, c_h3, c_h4, c_h5, c_h6 = st.columns([2, 2, 1, 1, 1, 2])
            c_h1.markdown(f"**{repo_name}**<br/><span style='font-size:0.8rem; color:#64748B;'>{r.repo_url}</span>", unsafe_allow_html=True)
            c_h2.markdown(f"{r.user_email}<br/><span style='font-size:0.8rem; color:#64748B;'>{r.created_at[:16]}</span>", unsafe_allow_html=True)
            c_h3.markdown(f"**{r.risk_score}** / {sum(1 for f in r.findings if f.severity=='CRITICAL')} C", unsafe_allow_html=True)
            dur = f"{r.intelligence.scan_duration}s" if r.intelligence else "N/A"
            c_h4.write(dur)
            c_h5.markdown(get_status_badge(r.status, r.current_stage), unsafe_allow_html=True)
            
            with c_h6:
                with st.popover("Endorse Action"):
                    fdbk = st.text_input("Review Notes (Required)", key=f"note_{r.id}")
                    if st.button("Approve Deployment", key=f"app_{r.id}", type="primary"):
                        WorkflowManager.approve_review(r.id, fdbk if fdbk else "Approved via dashboard.")
                        st.rerun()
                    if st.button("Reject / Fail Pipeline", key=f"rej_{r.id}"):
                        WorkflowManager.reject_review(r.id, fdbk if fdbk else "Rejected via dashboard.")
                        st.rerun()
            st.markdown("<hr style='margin-top:0.5rem; margin-bottom:0.5rem;'/>", unsafe_allow_html=True)

# --- PAGE: Scan History ---
elif menu == "Scan History":
    st.markdown("<h1 class='main-header'>📜 Global Pipeline Tracking</h1>", unsafe_allow_html=True)
    st.markdown("<p class='sub-header'>Deep inspection, tracking, and sorting logs of security scan executions.</p>", unsafe_allow_html=True)
    
    reviews = WorkflowManager.get_all_reviews(st.session_state.user_email, st.session_state.user_role)
    if not reviews:
        st.info("No logs present on the system database registries.")
    else:
        st.markdown("<h3 class='section-header'>Filter Parameters</h3>", unsafe_allow_html=True)
        f1, f2, f3, f4, f5 = st.columns(5)
        h_repo = f1.text_input("Repository Match")
        h_dev = f2.text_input("Developer Match")
        h_stat = f3.selectbox("Status Map", ["ALL", "Completed", "Running", "Failed", "Approved", "Rejected"])
        h_risk = f4.slider("Max Risk Threshold Limit", 0, 100, 100)
        h_sort = f5.selectbox("Sort Execution List", ["Newest", "Oldest", "Highest Risk", "Lowest Risk"])
            
        filtered = []
        for r in reviews:
            repo_name = r.repo_url.split('/')[-1].lower()
            if (not h_repo or h_repo.lower() in repo_name) and \
               (not h_dev or h_dev.lower() in r.user_email.lower()) and \
               (h_stat == "ALL" or r.status.value.lower() == h_stat.lower()) and \
               (r.risk_score <= h_risk):
                filtered.append(r)
                
        if h_sort == "Newest": filtered.sort(key=lambda x: x.created_at, reverse=True)
        elif h_sort == "Oldest": filtered.sort(key=lambda x: x.created_at)
        elif h_sort == "Highest Risk": filtered.sort(key=lambda x: x.risk_score, reverse=True)
        elif h_sort == "Lowest Risk": filtered.sort(key=lambda x: x.risk_score)
            
        st.markdown(f"Displaying **{len(filtered)}** historic review records.")
        for r in filtered:
            st.markdown(f"""
            <div style="background-color: white; border: 1px solid #E2E8F0; border-radius: 12px; padding: 1.5rem; margin-bottom: 1rem; box-shadow: 0 1px 2px 0 rgba(0,0,0,0.02);">
                <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #F1F5F9; padding-bottom: 0.75rem; margin-bottom: 0.75rem;">
                    <div>
                        <h4 style="margin: 0; color: #1E3A8A; font-size: 1.15rem;">📁 {r.repo_url.split('/')[-1]}</h4>
                        <span style="font-size: 0.8rem; color: #64748B;">Pipeline Trigger: {r.user_email}</span>
                    </div>
                    <div>
                        {get_status_badge(r.status, r.current_stage)}
                    </div>
                </div>
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div style="font-size: 0.85rem; color: #475569;">
                        📌 Tracker: <code>{r.id}</code> | 
                        ⚡ Risk Index: <strong>{r.risk_score}/100</strong> | 
                        📅 Trigger Date: {r.created_at.replace('T', ' ')[:19]}
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

# --- PAGE: Report Center ---
elif menu == "Report Center":
    st.markdown("<h1 class='main-header'>📑 Corporate Report Exports</h1>", unsafe_allow_html=True)
    st.markdown("<p class='sub-header'>Download finalized reports for offline compliance auditing and review storage.</p>", unsafe_allow_html=True)
    
    completed = [r for r in WorkflowManager.get_all_reviews(st.session_state.user_email, st.session_state.user_role) if r.status in [ReviewStatus.COMPLETED, ReviewStatus.APPROVED, ReviewStatus.REJECTED]]
    
    if not completed:
        st.info("No completed pipelines available to synthesize artifact downloads.")
    else:
        for r in completed:
            repo_name = r.repo_url.split('/')[-1]
            with st.expander(f"📦 Audit Export: {repo_name} | Scope: {r.id} | Risk: {r.risk_score}", expanded=False):
                st.markdown(f"**Executive Synthesis Summary:**\n{r.executive_summary}")
                
                # Setup Download Outputs (Mocking PDF via Text structure as allowed, HTML & JSON proper maps)
                json_data = json.dumps({
                    "id": r.id, "repo": r.repo_url, "risk": r.risk_score, "findings": [f.title for f in r.findings]
                }, indent=4)
                
                html_data = f"<html><body><h1>ReBIT Security Report: {repo_name}</h1><p>Risk Score: {r.risk_score}</p><p>{r.executive_summary}</p></body></html>"
                
                pdf_mock_text = f"REBIT AI SSDLC OFFICIAL AUDIT\n\nRepository: {r.repo_url}\nPipeline Ref: {r.id}\nScore: {r.risk_score}\n\nSummary:\n{r.executive_summary}"
                
                c1, c2, c3, c4 = st.columns(4)
                with c1:
                    st.download_button("💾 Download JSON Payload", data=json_data, file_name=f"ReBIT_Audit_{r.id}.json", mime="application/json", use_container_width=True)
                with c2:
                    st.download_button("🌐 Download HTML Report", data=html_data, file_name=f"ReBIT_Audit_{r.id}.html", mime="text/html", use_container_width=True)
                with c3:
                    st.download_button("📄 Download PDF (Text)", data=pdf_mock_text, file_name=f"ReBIT_Audit_{r.id}.txt", mime="text/plain", use_container_width=True)
                with c4:
                    if st.button("Interactive UI Inspection", key=f"insp_{r.id}", use_container_width=True):
                        st.session_state.current_scan_id = r.id
                        st.session_state.current_view_id = r.id
                        st.rerun()

# --- Fallback Inspector View overlay if triggered by User clicks anywhere in UI ---
if st.session_state.current_view_id:
    s_id = st.session_state.current_view_id
    session = review_store.get(s_id)
    if session:
        st.write("---")
        st.markdown(f"### 🔍 Deep Audit Modal: `{session.id}`")
        if st.button("Close Inspector Focus Console", type="secondary"):
            st.session_state.current_view_id = None
            st.rerun()
        st.json({
            "Pipeline Ref": session.id,
            "Repository Context": session.repo_url,
            "Total Flags Generated": len(session.findings),
            "Critical Violations": sum(1 for f in session.findings if f.severity=="CRITICAL")
        })