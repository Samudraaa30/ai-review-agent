import streamlit as st
import sys
from pathlib import Path

sys.path.append(
    str(Path(__file__).parent.parent)
)

from backend.clone_repo import clone_repository
from backend.scanner import discover_files

# Input Validation Pipeline
from backend.source_detector import detect_sources
from backend.validation_detector import detect_validations
from backend.sink_detector import detect_sinks
from backend.finding_engine import generate_findings
from backend.metrics import severity_counts

# Secrets Pipeline
from backend.secret_detector import detect_secrets

# Authentication Pipeline
from backend.auth_detector import detect_auth
from backend.auth_report import generate_auth_findings
from backend.authorization_detector import detect_authorization
from backend.authorization_report import generate_authorization_findings

# AST Analysis
from backend.ast_analyzer import analyze_python_ast
from backend.java_ast import analyze_java

#   AI Review Engine
from backend.ai_reviewer import review_finding
from backend.executive_summary import generate_summary

#Risk Score
from backend.risk_score import calculate_risk_score

#PDF
from backend.pdf_report import generate_pdf_report

from backend.scan_history import (
    save_scan,
    load_history
)

from backend.repository_comparison import (
    compare_repositories
)

# Enterprise Workflow Management
from backend.services.workflow_manager import (
    WorkflowManager,
    WorkflowStore,
    ScanStage,
    ScanStatus
)

from backend.dashboard_metrics import (
    calculate_dashboard_metrics
)

from backend.language_detector import (
    detect_language
)

from backend.reasoning_agent import (
    select_relevant_files
)

from backend.snippet_extractor import (
    extract_relevant_snippets
)

from backend.ai_reasoning_agent import (
    select_relevant_files_ai
)

from backend.function_extractor import (
    extract_functions
)

from backend.dependency_tracer import (
    trace_dependencies
)

from backend.dependency_detector import (
    detect_dependencies
)

from backend.dependency_security import (
    dependency_security_review
)

from backend.logging_detector import (
    detect_logging
)

from backend.html_report import (
    generate_html_report
)

from backend.tool_runner import (
    run_tool
)

from backend.repository_indexer import (
    build_repository_index
)

from backend.chunk_generator import (
    generate_chunks
)

from backend.chunk_reviewer import (
    review_chunk
)

from backend.review_store import (
    load_reviews,
    save_reviews
)
from datetime import datetime

from backend.auth_store import (
    load_users,
    save_users,
    verify_password
)

from backend.logging_detector import (
    detect_logging
)

from backend.whitelist_detector import (
    detect_whitelisting
)

from backend.audit_trail import log_action

from backend.rbac import has_permission

st.set_page_config(
    page_title="ReBIT Security Review Platform",
    layout="wide",
    page_icon="🔒"
)

# Custom CSS for ReBIT branding
st.markdown("""
<style>
    .rebit-header {
        background: linear-gradient(90deg, #1e3a8a 0%, #3b82f6 100%);
        padding: 1.5rem;
        border-radius: 0.75rem;
        margin-bottom: 1.5rem;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    .rebit-header h1 {
        color: white;
        margin: 0;
        font-size: 2rem;
    }
    .rebit-header p {
        color: rgba(255, 255, 255, 0.9);
        margin: 0.5rem 0 0 0;
    }
    .role-badge {
        display: inline-block;
        padding: 0.25rem 0.75rem;
        border-radius: 9999px;
        font-size: 0.875rem;
        font-weight: 600;
        margin-top: 0.5rem;
    }
    .role-admin { background: #dcfce7; color: #16a34a; }
    .role-auditor { background: #fef3c7; color: #d97706; }
    .role-manager { background: #dbeafe; color: #2563eb; }
    .role-developer { background: #f3f4f6; color: #4b5563; }
    .stButton>button {
        border-radius: 0.5rem;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "username" not in st.session_state:
    st.session_state.username = None

if "role" not in st.session_state:
    st.session_state.role = None

if not st.session_state.logged_in:
    # Header for login page
    st.markdown("""
    <div class="rebit-header">
        <h1>🔒 ReBIT Security Review Platform</h1>
        <p>Enterprise AI-Powered SSDLC Security Review Agent</p>
    </div>
    """, unsafe_allow_html=True)
    
    tab1, tab2 = st.tabs(["Login", "Register"])

    with tab1:
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            st.markdown("### Welcome Back")
            username = st.text_input("Username", key="login_user")
            password = st.text_input("Password", type="password", key="login_pass")

            if st.button("Login", type="primary", use_container_width=True):
                users = load_users()
                
                # Try new password verification first
                result = verify_password(username, password)
                
                if result:
                    st.session_state.logged_in = True
                    st.session_state.username = username
                    st.session_state.role = result["role"]
                    
                    # Log login action
                    log_action(
                        action_type="AUTH_LOGIN",
                        user=username,
                        details={"role": result["role"]}
                    )
                    
                    st.rerun()
                else:
                    # Fallback to old method for backward compatibility
                    for user in users:
                        if ("password" in user and user["username"] == username and user["password"] == password):
                            st.session_state.logged_in = True
                            st.session_state.username = username
                            st.session_state.role = user.get("role", "Developer")
                            
                            log_action(
                                action_type="AUTH_LOGIN",
                                user=username,
                                details={"role": st.session_state.role, "method": "legacy"}
                            )
                            
                            st.rerun()
                    
                    st.error("Invalid credentials")
            
            # Show default credentials hint
            with st.expander("📝 Default Credentials"):
                st.code("""
Admin: admin / admin
Developer: developer / developer
Manager: manager / manager
Auditor: auditor / auditor
                """)

    with tab2:
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            st.markdown("### Create Account")
            new_user = st.text_input("Username", key="register_user")
            new_pass = st.text_input("Password", type="password", key="register_pass")
            confirm_pass = st.text_input("Confirm Password", type="password", key="confirm_pass")

            role = st.selectbox(
                "Role",
                ["Developer", "Manager"],
                help="Auditor and Admin roles must be created by an administrator"
            )

            if st.button("Register", use_container_width=True):
                if not new_user or not new_pass:
                    st.error("Username and password are required")
                elif new_pass != confirm_pass:
                    st.error("Passwords do not match")
                elif len(new_pass) < 6:
                    st.error("Password must be at least 6 characters")
                else:
                    from backend.auth_store import create_user
                    
                    result = create_user(
                        username=new_user,
                        password=new_pass,
                        role=role,
                        created_by=new_user
                    )
                    
                    if "error" in result:
                        st.error(result["error"])
                    else:
                        st.success("Registration successful! Please login.")
                        
                        log_action(
                            action_type="AUTH_REGISTER",
                            user=new_user,
                            details={"role": role}
                        )

    st.stop()

# ==========================================
# AUTHENTICATED USER INTERFACE
# ==========================================

# Role-based navigation
available_pages = []

# All roles can access the main scanner
available_pages.append("🔍 Security Scanner")

# Add new Enterprise Scanner with 7-stage workflow
available_pages.append("🔒 Enterprise Scanner")

# Developer specific
if st.session_state.role in ["Developer", "Manager", "Admin"]:
    available_pages.append("📊 My Dashboard")

# Manager specific
if st.session_state.role in ["Manager", "Admin"]:
    available_pages.append("✅ Review Queue")

# Auditor specific  
if st.session_state.role in ["Auditor", "Admin"]:
    available_pages.append("🔍 Auditor Portal")

# Admin specific
if st.session_state.role == "Admin":
    available_pages.append("⚙️ Admin Portal")

# Set default page
if "current_page" not in st.session_state:
    st.session_state.current_page = "🔍 Security Scanner"

# Sidebar
with st.sidebar:
    # User info with branding
    role_class = f"role-{st.session_state.role.lower()}"
    st.markdown(f"""
    <div style="padding: 1rem; background: #f0f9ff; border-radius: 0.5rem; margin-bottom: 1rem;">
        <strong>👤 {st.session_state.username}</strong><br>
        <span class="role-badge {role_class}">{st.session_state.role}</span>
    </div>
    """, unsafe_allow_html=True)
    
    # Navigation
    st.session_state.current_page = st.radio(
        "Navigation",
        available_pages,
        label_visibility="collapsed"
    )
    
    st.divider()
    
    if st.button("🚪 Logout", use_container_width=True):
        log_action(
            action_type="AUTH_LOGOUT",
            user=st.session_state.username,
            details={"role": st.session_state.role}
        )
        
        st.session_state.logged_in = False
        st.session_state.username = None
        st.session_state.role = None
        st.session_state.current_page = None
        st.rerun()

# ==========================================
# PAGE ROUTING
# ==========================================

if st.session_state.current_page == "🔍 Auditor Portal":
    # Redirect to auditor portal
    import subprocess
    import sys
    st.info("Redirecting to Auditor Portal...")
    subprocess.run([sys.executable, "-m", "streamlit", "run", "frontend/auditor.py"])
elif st.session_state.current_page == "⚙️ Admin Portal":
    # Redirect to admin portal
    import subprocess
    import sys
    st.info("Redirecting to Admin Portal...")
    subprocess.run([sys.executable, "-m", "streamlit", "run", "frontend/admin.py"])
elif st.session_state.current_page == "✅ Review Queue":
    # Show manager review queue inline
    from backend.review_store import load_reviews, save_reviews
    
    reviews = load_reviews() or []
    
    st.title("✅ Review Queue")
    
    filter_status = st.selectbox(
        "Filter by Status",
        ["All", "Pending", "Approved", "Rejected"]
    )
    
    pending = len([r for r in reviews if r.get("status") == "Pending"])
    approved = len([r for r in reviews if r.get("status") == "Approved"])
    rejected = len([r for r in reviews if r.get("status") == "Rejected"])
    
    c1, c2, c3 = st.columns(3)
    c1.metric("Pending Reviews", pending)
    c2.metric("Approved Reviews", approved)
    c3.metric("Rejected Reviews", rejected)
    
    filtered_reviews = reviews.copy()
    if filter_status != "All":
        filtered_reviews = [r for r in reviews if r.get("status") == filter_status]
    
    for i, review in enumerate(filtered_reviews):
        with st.expander(
            f"{review.get('repo', 'Unknown Repo')[:60]} - {review.get('review_type', 'N/A')}"
        ):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(f"**Review Type:** {review.get('review_type', 'N/A')}")
                st.write(f"**Risk Score:** {review.get('risk_score', 'N/A')}")
                st.write(f"**Submitted:** {review.get('timestamp', 'N/A')}")
                st.write(f"**Submitted By:** {review.get('submitted_by', 'N/A')}")
            
            with col2:
                st.write(f"**Status:** {review.get('status', 'Pending')}")
                st.write(f"**Manager Comment:** {review.get('manager_comment', 'None')}")
                
                pdf_path = review.get("pdf_path")
                if pdf_path:
                    try:
                        with open(pdf_path, "rb") as pdf_file:
                            st.download_button(
                                "📄 Download Report",
                                pdf_file,
                                file_name=f"Review_Report_{i}.pdf",
                                mime="application/pdf",
                                key=f"pdf_{i}"
                            )
                    except:
                        st.warning("Report not found")
            
            status = st.selectbox(
                "Status",
                ["Pending", "Approved", "Rejected"],
                key=f"status_{i}"
            )
            
            comment = st.text_area(
                "Manager Comment",
                value=review.get("manager_comment", ""),
                key=f"comment_{i}"
            )
            
            review["status"] = status
            review["manager_comment"] = comment
            
            st.divider()
    
    if st.button("💾 Save Reviews", key="save_reviews_btn"):
        save_reviews(reviews)
        st.success("Reviews Saved")
        
        log_action(
            action_type="REVIEW_SAVE",
            user=st.session_state.username,
            details={"count": len(reviews)}
        )

else:
    # Default: Security Scanner (Developer view)
    if st.session_state.role == "Developer":
 repo_url = st.text_input(
    "GitHub Repository URL"
 )

 review_type = st.selectbox(
    "Review Type",
    [
        "Input Validation",
        "Whitelisting Review",
        "Secrets Detection",
        "Authentication Review",
        "Authorization Review",
        "Dependency Security",
        "Logging & Monitoring"
    ]
 )

 if st.button("Scan Repository"):

    if not repo_url:

        st.error(
            "Please enter a repository URL"
        )

    else:

        with st.spinner(
            "Scanning Repository..."
        ):

            repo_path = clone_repository(
                repo_url
            )

            repository_index = build_repository_index(
                repo_path
            )

            tool_results = run_tool(
                review_type,
                repo_path
            )
            
            st.header(
               "🛠️ Plugin Architecture Test"
            )

            st.write(
                f"Tool Results: {len(tool_results)}"
            )
            language_info = detect_language(
               repo_path
            )

            relevant_files = select_relevant_files(
                repo_path,
                review_type
            )
            snippets = extract_relevant_snippets(
                relevant_files
            )
            chunks = generate_chunks(
                snippets
            )
            chunk_reviews = []

            for chunk in chunks[:3]:

                review = review_chunk(
                    chunk["chunk"]
                )

                chunk_reviews.append(
                     review
                )
            all_functions = []

            for file_path in relevant_files:

                funcs = extract_functions(
                    file_path
                )

                all_functions.extend(
                    funcs
                )
            files = discover_files(
                repo_path
            )
            file_names = [
                str(f)
                for f in files
            ]
            ai_reasoning = select_relevant_files_ai(
               file_names,
               review_type
            )
            ast_results = analyze_python_ast(
                repo_path
            )
            java_ast_results = analyze_java(
                repo_path
            )
            st.header(
                "🧠 Reasoning Agent"
            )

            st.metric(
                "Relevant Files Selected",
                len(relevant_files)
            )

            with st.expander(
                 "View Relevant Files"
            ):
                 st.write(
                    relevant_files
                )
            st.subheader(
                "AI File Selection"
            )

            st.code(
                ai_reasoning
            )
        # ==================================
        # INPUT VALIDATION REVIEW
        # ==================================

        if review_type == "Input Validation":

            sources = detect_sources(
                repo_path
            )

            validations = detect_validations(
                repo_path
            )

            sinks = detect_sinks(
                repo_path
            )

            findings = generate_findings(
                sources,
                validations,
                sinks
            )

            metrics = severity_counts(
                findings
            )
            risk_score = calculate_risk_score(
                findings
            )
            save_scan(
                repo_url,
                review_type,
                risk_score
            )
            summary = generate_summary(
                findings,
                len(sources),
                len(validations),
                len(sinks)
            )
            pdf_path = generate_pdf_report(
                "report.pdf",
                summary,
                findings,
                risk_score,
                metrics
            )
            html_path = generate_html_report(
                "report.html",
                summary,
                findings,
                risk_score
            )
            reviews = load_reviews()
            reviews.append(
             {
              "repo": repo_url,
              "review_type": review_type,
              "risk_score": risk_score,
              "pdf_path": pdf_path,
              "timestamp": datetime.now().strftime(
              "%d-%m-%Y %H:%M"
               ),
              "submitted_by": "Developer",
              "status": "Pending",
              "manager_comment": ""
             }
            )

            save_reviews(
             reviews
            )
            st.success(
                "Input Validation Review Complete"
            )
            st.header(
               "✂️ Extracted Snippets"
            )

            for snippet in snippets[:5]:

                with st.expander(
                   snippet["file"]
                ):

                   st.code(
                      snippet["snippet"]
                    )
            st.header(
                 "🧩 Chunk Generator"
                )

            st.metric(
                 "Chunks Generated",
                 len(chunks)
                )

            for chunk in chunks[:5]:

                with st.expander(
                     chunk["file"]
                ):

                     st.code(
                          chunk["chunk"]
                    )
            st.header(
                "🤖 AI Chunk Reviews"
            )

            for review in chunk_reviews:

                 st.write(
                 review
                )

                 st.divider()
            st.header(
                "⚙️ Extracted Functions"
            )

            st.write(
                all_functions[:50]
            )
            all_dependencies = []

            for file_path in relevant_files:

                deps = trace_dependencies(
                   file_path
                )

                all_dependencies.extend(
                    deps
                )
            st.header(
                "🔗 Function Dependencies"
            )

            st.write(
                all_dependencies[:50]
            )
            st.header(
                "🖥 Repository Information"
            )

            c1, c2 = st.columns(2)

            c1.metric(
                "Language",
                language_info["language"]
            )

            c2.metric(
               "Framework",
               "Unknown"
            )
            st.header(
                "AI Executive Summary"
            )

            st.write(
                summary
            )
            st.header(
                "📊 Risk Score"
           )
            with open(
               pdf_path,
               "rb"
            ) as pdf_file:

                st.download_button(
                    "📄 Download PDF Report",
                    pdf_file,
                    file_name="AI_SSDLC_Report.pdf",
                    mime="application/pdf"
            )
            with open(
               html_path,
               "rb"
            ) as html_file:

                st.download_button(
                    "🌐 Download HTML Report",
                    html_file,
                    file_name="AI_SSDLC_Report.html",
                    mime="text/html"
                )
            st.metric(
                "Repository Risk Score",
                f"{risk_score}/100"
           )    
            st.header(
                "🖥️ Repository Profile"
            )

            col1, col2 = st.columns(2)

            col1.metric(
                "Primary Language",
                language_info["language"]
            )

            col2.metric(
               "Source Files",
               len(files)
            )

            st.json(
               language_info["counts"]
            )
            st.header(
               "📚 Repository Index"
            )

            col1, col2, col3, col4 = st.columns(4)

            col1.metric(
                "Python",
                repository_index["python_files"]
            )

            col2.metric(
                "Java",
                repository_index["java_files"]
            )

            col3.metric(
                "JavaScript",
                repository_index["js_files"]
            )

            col4.metric(
            
                "TypeScript",
                repository_index["ts_files"]
            )
            st.header(
                "Repository Summary"
            )

            col1, col2, col3, col4, col5 = st.columns(5)

            col1.metric(
                "Files",
                len(files)
            )

            col2.metric(
                "Sources",
                len(sources)
            )

            col3.metric(
                "Validations",
                len(validations)
            )

            col4.metric(
                "Sinks",
                len(sinks)
            )

            col5.metric(
                "Findings",
                len(findings)
            )

            st.header(
                "AST Summary"
            )

            a1, a2 = st.columns(2)

            a1.metric(
                "Functions Found",
                len(
                    ast_results["functions"]
                )
            )
            st.header("Java AST Summary")

            j1, j2 = st.columns(2)

            j1.metric(
               "Java Classes",
               len(
                  java_ast_results["classes"]
                )
        )

            j2.metric(
                "Java Methods",
                len(
                   java_ast_results["methods"]
                )
            )

            a2.metric(
                "Classes Found",
                len(
                    ast_results["classes"]
                )
            )

            with st.expander(
                "View Functions"
            ):

                st.write(
                    ast_results["functions"][:50]
                )

            with st.expander(
                "View Classes"
            ):

                st.write(
                    ast_results["classes"][:50]
                )

            st.header(
                "Risk Distribution"
            )

            r1, r2, r3, r4 = st.columns(4)

            r1.metric(
                "CRITICAL",
                metrics["CRITICAL"]
            )

            r2.metric(
                "HIGH",
                metrics["HIGH"]
            )

            r3.metric(
                "MEDIUM",
                metrics["MEDIUM"]
            )

            r4.metric(
                "LOW",
                metrics["LOW"]
            )

            st.header(
                "Security Findings"
            )

            for finding in findings[:10]:

                with st.expander(
                    f"{finding['severity']} - {finding['source']}"
                ):

                    st.write(
                        f"Status: {finding['status']}"
                    )

                    st.write(
                        f"File: {finding['file']}"
                    )

                    st.write(
                        f"Line: {finding['line']}"
                    )

                    st.write(
                        f"Issue: {finding['issue']}"
                    )

                    st.write(
                        f"Recommendation: {finding['recommendation']}"
                    )

                    st.code(
                        finding["snippet"]
                    )
                    with st.spinner(
                        "Generating AI Review..."
                    ):

                        review = review_finding(
                            finding
                              )
                    st.markdown(
                        "### 🤖 Gemini Security Review"
                    )
                    st.write(
                        review
                    )
            st.header(
             "📋 Manager Feedback"
            )

            reviews = load_reviews()

            for review in reviews:

              if review.get("repo") == repo_url:

               status = review.get("status", "Pending")
               st.success(
               f"Status: {status}"
               )
               if status == "Approved":

                st.success(
                  "✅ APPROVED"
                )

               elif status == "Rejected":

                st.error(
                 "❌ REJECTED"
                )

               else:

                st.warning(
                 "⏳ PENDING"
                )
               st.write(
                 f"Manager Comment: {review.get('manager_comment','')}"
               ) 
            
            st.header(
                "📈 Scan History"
            )
            
            history = load_history()

            if history:

                st.dataframe(
                history
            )

            else:

                st.info(
                "No scan history available."
            )
            st.header(
                "⚖️ Repository Comparison"
            )

            comparison = compare_repositories(
                history
            )

            if comparison:

                c1, c2 = st.columns(2)

                c1.metric(
                    comparison["previous_repo"],
                    comparison["previous_score"]
                )

                c2.metric(
                   comparison["latest_repo"],
                   comparison["latest_score"]
                )

                st.metric(
                   "Risk Difference",
                   comparison["difference"]
                )

            else:

                st.info(
                    "Scan at least two repositories to compare."
                )
            
            st.header(
              "📊 Manager Dashboard"
            )

            dashboard = calculate_dashboard_metrics(
              history
            )

            if dashboard:

              d1, d2, d3, d4 = st.columns(4)

              d1.metric(
                  "Repositories",
                  dashboard["total_repositories"]
              )

              d2.metric(
                  "Average Risk",
                  dashboard["average_risk"]
              )

              d3.metric(
                  "Highest Risk",
                  dashboard["highest_score"]
             )

              d4.metric(
                  "Latest Scan",
                  dashboard["latest_repo"]
             )

            else:

              st.info(
                  "No dashboard data available."
             )
        # ==================================
        # SECRETS DETECTION
        # ==================================

        elif review_type == "Secrets Detection":

            secrets = detect_secrets(
                repo_path
            )

            st.success(
                "Secrets Detection Complete"
            )

            st.header(
                "Repository Summary"
            )

            col1, col2 = st.columns(2)

            col1.metric(
                "Files",
                len(files)
            )

            col2.metric(
                "Secrets Found",
                len(secrets)
            )

            st.header(
                "Detected Secrets"
            )

            if len(secrets) == 0:

                st.info(
                    "No secrets detected."
                )

            else:

                for secret in secrets[:20]:

                    st.json(
                        secret
                    )

        # ==================================
        # AUTHENTICATION REVIEW
        # ==================================

        elif review_type == "Authentication Review":

            auth_matches = detect_auth(
                repo_path
            )

            auth_findings = generate_auth_findings(
                auth_matches
            )

            st.success(
                "Authentication Review Complete"
            )

            st.header(
                "Authentication Summary"
            )

            col1, col2 = st.columns(2)

            col1.metric(
                "Files",
                len(files)
            )

            col2.metric(
                "Authentication Patterns",
                len(auth_findings)
            )

            st.header(
                "AST Summary"
            )

            a1, a2 = st.columns(2)

            a1.metric(
                "Functions Found",
                len(
                    ast_results["functions"]
                )
            )

            a2.metric(
                "Classes Found",
                len(
                    ast_results["classes"]
                )
            )

            st.header(
                "Authentication Findings"
            )

            if len(auth_findings) == 0:

                st.info(
                    "No authentication patterns found."
                )

            else:

                for finding in auth_findings[:20]:

                    with st.expander(
                        finding["issue"]
                    ):

                        st.write(
                            f"Severity: {finding['severity']}"
                        )

                        st.write(
                            f"Status: {finding['status']}"
                        )

                        st.write(
                            f"File: {finding['file']}"
                        )

                        st.write(
                            f"Line: {finding['line']}"
                        )

                        st.write(
                            finding["recommendation"]
                        )

                        st.code(
                            finding["code"]
                        ) 
        # ==================================
        # AUTHORIZATION REVIEW
        # ==================================

        elif review_type == "Authorization Review":

            authz_matches = detect_authorization(
                repo_path
            )

            authz_findings = generate_authorization_findings(
                authz_matches
            )

            st.success(
                "Authorization Review Complete"
            )

            st.header(
                "Authorization Summary"
            )

            col1, col2 = st.columns(2)

            col1.metric(
                "Files",
                len(files)
            )

            col2.metric(
                "Authorization Patterns",
                len(authz_findings)
            )

            st.header(
                "AST Summary"
            )

            a1, a2 = st.columns(2)

            a1.metric(
                "Functions Found",
                len(
                    ast_results["functions"]
                )
            )

            a2.metric(
                "Classes Found",
                len(
                    ast_results["classes"]
                )
            )

            st.header(
                "Authorization Findings"
            )

            if len(authz_findings) == 0:

                st.info(
                    "No authorization patterns found."
                )

            else:

                for finding in authz_findings[:20]:

                    with st.expander(
                        finding["issue"]
                    ):

                        st.write(
                            f"Severity: {finding['severity']}"
                        )

                        st.write(
                            f"Status: {finding['status']}"
                        )

                        st.write(
                            f"File: {finding['file']}"
                        )

                        st.write(
                            f"Line: {finding['line']}"
                        )

                        st.write(
                            finding["recommendation"]
                        )

                        st.code(
                            finding["code"]
                        )
        #==================================
        # DEPENDENCY SECURITY REVIEW
        #==================================
        
        elif review_type == "Dependency Security":

            audit_findings = dependency_security_review(
              repo_path
            )

            st.header(
                "📦 npm Audit Findings"
            )

            for finding in audit_findings:

                st.write(
                    finding
            )
            dependency_findings = detect_dependencies(
                repo_path
            )

            st.success(
                "Dependency Security Review Complete"
            )

            st.header(
                "Dependency Summary"
            )

            col1, col2 = st.columns(2)

            col1.metric(
                "Files",
                len(files)
            )

            col2.metric(
                "Dependency Files Found",
                len(dependency_findings)
            )

            st.header(
                "Dependency Findings"
            )

            if len(dependency_findings) == 0:

                st.info(
                    "No dependency files found."
                )

            else:

                for finding in dependency_findings[:20]:

                    with st.expander(
                        finding["file"]
                    ):

                        st.write(
                            f"Issue: {finding['issue']}"
                        )

                        st.code(
                            finding["content"]
                        )
        #==================================
        # LOGGING & MONITORING REVIEW
        #==================================
        elif review_type == "Logging & Monitoring":

            logs = detect_logging(
                repo_path
            )

            st.success(
                "Logging & Monitoring Review Complete"
            )

            st.metric(
                "Logging Events",
                len(logs)
            )

            if logs:

                for log in logs[:20]:

                    with st.expander(
                        log["pattern"]
                    ):

                        st.write(
                            f"File: {log['file']}"
                        )

                        st.write(
                            f"Line: {log['line']}"
                        )

                        st.code(
                            log["code"]
                        )

            else:

                st.info(
                    "No logging controls detected."
                )
        elif review_type == "Whitelisting Review":

         whitelist_findings = detect_whitelisting(
         repo_path
        )

         st.success(
          "Whitelisting Review Complete"
        )

         st.metric(
          "Whitelisting Controls Found",
           len(
              whitelist_findings
            )
        )

         if whitelist_findings:

          for finding in whitelist_findings[:20]:

            with st.expander(
                finding["file"]
            ):

                st.write(
                    f"Line: {finding['line']}"
                )

                st.code(
                    finding["code"]
                )

        else:

          st.info(
            "No whitelisting controls found."
        )
          
elif st.session_state.role == "Manager":

    reviews = load_reviews() or []

    manager_page = st.sidebar.radio(
        "Manager Menu",
        [
            "Review Queue",
            "Dashboard"
        ]
    )

    # ==========================
    # REVIEW QUEUE
    # ==========================

    if manager_page == "Review Queue":

        st.title("📊 Manager Portal")

        filter_status = st.selectbox(
            "Filter",
            [
                "All",
                "Pending",
                "Approved",
                "Rejected"
            ]
        )

        pending = len(
            [
                r for r in reviews
                if r.get("status", "Pending") == "Pending"
            ]
        )

        approved = len(
            [
                r for r in reviews
                if r.get("status", "Pending") == "Approved"
            ]
        )

        rejected = len(
            [
                r for r in reviews
                if r.get("status", "Pending") == "Rejected"
            ]
        )

        c1, c2, c3 = st.columns(3)

        c1.metric(
            "Pending Reviews",
            pending
        )

        c2.metric(
            "Approved Reviews",
            approved
        )

        c3.metric(
            "Rejected Reviews",
            rejected
        )

        report_file = "report.pdf"

        for i, review in enumerate(reviews):

            if (
                filter_status != "All"
                and review.get(
                    "status",
                    "Pending"
                ) != filter_status
            ):
                continue

            st.subheader(
                review.get(
                    "repo",
                    "Unknown Repo"
                )
            )

            st.write(
                f"Review Type: {review.get('review_type','N/A')}"
            )

            st.write(
                f"Risk Score: {review.get('risk_score','N/A')}"
            )

            pdf_path = review.get(
                "pdf_path"
            )

            if pdf_path:

                try:

                    with open(
                        pdf_path,
                        "rb"
                    ) as pdf_file:

                        st.download_button(
                            "📄 Download Report",
                            pdf_file,
                            file_name="Review_Report.pdf",
                            mime="application/pdf",
                            key=f"pdf_{i}"
                        )

                except:

                    st.warning(
                        "Report not found"
                    )

            st.write(
                f"Submitted: {review.get('timestamp','N/A')}"
            )

            st.write(
                f"Submitted By: {review.get('submitted_by','N/A')}"
            )

            st.write(
                f"Current Status: {review.get('status','Pending')}"
            )

            status = st.selectbox(
                "Status",
                [
                    "Pending",
                    "Approved",
                    "Rejected"
                ],
                key=f"status_{i}"
            )

            comment = st.text_area(
                "Manager Comment",
                value=review.get(
                    "manager_comment",
                    ""
                ),
                key=f"comment_{i}"
            )

            review["status"] = status
            review["manager_comment"] = comment

            st.divider()

        if st.button(
            "💾 Save Reviews",
            key="save_reviews_btn"
        ):

            save_reviews(
                reviews
            )

            st.success(
                "Reviews Saved"
            )

    # ==========================
    # DASHBOARD
    # ==========================

    elif manager_page == "Dashboard":

        st.title(
            "📊 Manager Dashboard"
        )

        total_reviews = len(
            reviews
        )

        pending = len(
            [
                r for r in reviews
                if r.get(
                    "status",
                    "Pending"
                ) == "Pending"
            ]
        )

        approved = len(
            [
                r for r in reviews
                if r.get(
                    "status",
                    "Pending"
                ) == "Approved"
            ]
        )

        rejected = len(
            [
                r for r in reviews
                if r.get(
                    "status",
                    "Pending"
                ) == "Rejected"
            ]
        )

        risk_scores = [
            r.get(
                "risk_score",
                0
            )
            for r in reviews
        ]

        avg_risk = (
            round(
                sum(risk_scores) /
                len(risk_scores),
                2
            )
            if risk_scores
            else 0
        )

        c1, c2, c3, c4 = st.columns(4)

        c1.metric(
            "Total Reviews",
            total_reviews
        )

        c2.metric(
            "Pending",
            pending
        )

        c3.metric(
            "Approved",
            approved
        )

        c4.metric(
            "Rejected",
            rejected
        )

        st.metric(
            "Average Risk Score",
            avg_risk
        )

        if reviews:

            highest = max(
                reviews,
                key=lambda x:
                x.get(
                    "risk_score",
                    0
                )
            )

            st.subheader(
                "🚨 Highest Risk Repository"
            )

            st.write(
                highest.get(
                    "repo",
                    "N/A"
                )
            )

            st.write(
                f"Risk Score: {highest.get('risk_score',0)}"
            )

            st.subheader(
                "📋 Recent Reviews"
            )

            st.dataframe(
                reviews[-10:]
            )