"""
Auditor Portal - Read-only access for compliance and audit review
ReBIT Security Review Platform
"""
import streamlit as st
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from backend.auth_store import load_users, verify_password
from backend.review_store import load_reviews
from backend.scan_history import load_history
from backend.audit_trail import get_audit_logs, verify_integrity, export_audit_logs
from backend.finding_filters import apply_filters_and_sort, get_severity_summary
from backend.dashboard_metrics import calculate_dashboard_metrics
from backend.rbac import has_permission, get_role_description
from datetime import datetime

st.set_page_config(
    page_title="Auditor Portal - ReBIT",
    layout="wide",
    page_icon="🔍"
)

# Custom CSS for ReBIT branding
st.markdown("""
<style>
    .rebit-header {
        background: linear-gradient(90deg, #1e3a8a 0%, #3b82f6 100%);
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
    }
    .rebit-header h1 {
        color: white;
        margin: 0;
    }
    .metric-card {
        background: #f0f9ff;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #3b82f6;
    }
    .status-badge {
        padding: 0.25rem 0.75rem;
        border-radius: 9999px;
        font-size: 0.875rem;
        font-weight: 600;
    }
    .status-open { background: #fee2e2; color: #dc2626; }
    .status-fixed { background: #dcfce7; color: #16a34a; }
    .status-fp { background: #fef3c7; color: #d97706; }
</style>
""", unsafe_allow_html=True)

# Check authentication
if "logged_in" not in st.session_state or not st.session_state.logged_in:
    st.warning("Please log in to access the Auditor Portal")
    st.switch_page("app.py")
    st.stop()

if st.session_state.role not in ["Auditor", "Admin"]:
    st.error("Access Denied: This portal is only available to Auditors and Administrators")
    st.stop()

# Header
st.markdown("""
<div class="rebit-header">
    <h1>🔍 ReBIT Auditor Portal</h1>
    <p style="color: rgba(255,255,255,0.9); margin: 0.5rem 0 0 0;">
        Compliance Review & Security Audit Dashboard
    </p>
</div>
""", unsafe_allow_html=True)

st.sidebar.success(f"Logged in as **{st.session_state.username}** ({st.session_state.role})")

# Sidebar navigation
audit_page = st.sidebar.radio(
    "Navigation",
    [
        "📊 Executive Dashboard",
        "🔍 Findings Browser",
        "📋 Review Queue",
        "📜 Audit Trail",
        "📈 Scan History",
        "📄 Reports Archive",
        "✅ Integrity Check"
    ]
)

if st.sidebar.button("🚪 Logout"):
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.role = None
    st.rerun()

# Load data
reviews = load_reviews() or []
history = load_history() or []

# ==========================================
# EXECUTIVE DASHBOARD
# ==========================================
if audit_page == "📊 Executive Dashboard":
    st.title("Executive Dashboard")
    
    # Calculate metrics
    metrics = calculate_dashboard_metrics(history)
    
    if metrics:
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Total Scans",
                metrics.get("total_repositories", 0),
                delta="All time"
            )
        
        with col2:
            st.metric(
                "Average Risk Score",
                metrics.get("average_risk", 0),
                delta="Across all scans"
            )
        
        with col3:
            st.metric(
                "Highest Risk",
                metrics.get("highest_score", 0),
                delta=metrics.get("highest_repo", "N/A")[:30]
            )
        
        with col4:
            st.metric(
                "Latest Scan",
                "Recent",
                delta=metrics.get("latest_repo", "N/A")[:30]
            )
    
    # Review status summary
    st.subheader("Review Status Overview")
    
    pending = len([r for r in reviews if r.get("status") == "Pending"])
    approved = len([r for r in reviews if r.get("status") == "Approved"])
    rejected = len([r for r in reviews if r.get("status") == "Rejected"])
    
    col1, col2, col3 = st.columns(3)
    
    col1.metric("Pending Reviews", pending)
    col2.metric("Approved Reviews", approved)
    col3.metric("Rejected Reviews", rejected)
    
    # Recent activity
    st.subheader("Recent Reviews")
    
    if reviews:
        recent_data = []
        for review in reviews[-10:]:
            recent_data.append({
                "Repository": review.get("repo", "Unknown")[:50],
                "Type": review.get("review_type", "N/A"),
                "Risk Score": review.get("risk_score", 0),
                "Status": review.get("status", "Pending"),
                "Date": review.get("timestamp", "N/A")
            })
        
        st.dataframe(recent_data, use_container_width=True, hide_index=True)

# ==========================================
# FINDINGS BROWSER
# ==========================================
elif audit_page == "🔍 Findings Browser":
    st.title("Findings Browser")
    
    st.info("Browse and filter security findings across all scans")
    
    # Sample findings from reviews (in real implementation, would come from findings store)
    sample_findings = []
    for review in reviews:
        sample_findings.append({
            "repo": review.get("repo"),
            "review_type": review.get("review_type"),
            "severity": "HIGH" if review.get("risk_score", 0) > 70 else "MEDIUM",
            "status": "Open",
            "issue": f"Security finding in {review.get('review_type')}",
            "file": "sample.py",
            "line": 1,
            "code": "# Sample code"
        })
    
    # Filters
    col1, col2, col3 = st.columns(3)
    
    with col1:
        severity_filter = st.selectbox(
            "Severity",
            ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
        )
    
    with col2:
        type_filter = st.selectbox(
            "Review Type",
            ["All"] + list(set(r.get("review_type", "") for r in reviews))
        )
    
    with col3:
        status_filter = st.selectbox(
            "Status",
            ["All", "Open", "Fixed", "False Positive", "Won't Fix"]
        )
    
    search_query = st.text_input("🔍 Search Findings", placeholder="Search by issue, file, or code...")
    
    # Apply filters
    if sample_findings:
        filtered = apply_filters_and_sort(
            sample_findings,
            filters={
                "severity": severity_filter if severity_filter != "All" else None,
                "review_type": type_filter if type_filter != "All" else None,
                "status": status_filter if status_filter != "All" else None,
                "search_query": search_query if search_query else None
            },
            page=1,
            page_size=20
        )
        
        st.write(f"**{filtered['total_items']}** findings found")
        
        # Display findings
        for finding in filtered["items"]:
            with st.expander(
                f"{finding.get('severity', 'UNKNOWN')} - {finding.get('issue', 'Unknown Issue')}"
            ):
                col1, col2 = st.columns(2)
                col1.write(f"**File:** {finding.get('file', 'N/A')}")
                col2.write(f"**Line:** {finding.get('line', 'N/A')}")
                st.code(finding.get('code', ''))
    else:
        st.info("No findings available. Run a security scan first.")

# ==========================================
# REVIEW QUEUE
# ==========================================
elif audit_page == "📋 Review Queue":
    st.title("Review Queue")
    
    st.info("View all submitted reviews (read-only access)")
    
    # Filter options
    filter_status = st.selectbox(
        "Filter by Status",
        ["All", "Pending", "Approved", "Rejected"]
    )
    
    filtered_reviews = reviews.copy()
    if filter_status != "All":
        filtered_reviews = [r for r in reviews if r.get("status") == filter_status]
    
    st.write(f"**{len(filtered_reviews)}** reviews found")
    
    for i, review in enumerate(filtered_reviews):
        with st.expander(
            f"{review.get('repo', 'Unknown Repo')[:60]} - {review.get('review_type', 'N/A')}"
        ):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(f"**Review Type:** {review.get('review_type', 'N/A')}")
                st.write(f"**Risk Score:** {review.get('risk_score', 'N/A')}")
                st.write(f"**Submitted:** {review.get('timestamp', 'N/A')}")
            
            with col2:
                st.write(f"**Submitted By:** {review.get('submitted_by', 'N/A')}")
                st.write(f"**Status:** {review.get('status', 'Pending')}")
                st.write(f"**Manager Comment:** {review.get('manager_comment', 'None')}")
            
            # Download report if available
            pdf_path = review.get("pdf_path")
            if pdf_path:
                try:
                    with open(pdf_path, "rb") as pdf_file:
                        st.download_button(
                            "📄 Download Report",
                            pdf_file,
                            file_name=f"Audit_Report_{i}.pdf",
                            mime="application/pdf",
                            key=f"audit_pdf_{i}"
                        )
                except:
                    st.warning("Report file not found")

# ==========================================
# AUDIT TRAIL
# ==========================================
elif audit_page == "📜 Audit Trail":
    st.title("Audit Trail")
    
    st.info("Immutable log of all system actions")
    
    # Filter options
    col1, col2 = st.columns(2)
    
    with col1:
        action_type = st.selectbox(
            "Action Type",
            ["All", "AUTH_LOGIN", "SCAN_INITIATE", "REVIEW_APPROVE", "REVIEW_REJECT"]
        )
    
    with col2:
        limit = st.slider("Max Entries", 10, 100, 50)
    
    # Get audit logs
    logs = get_audit_logs(
        action_type=action_type if action_type != "All" else None,
        limit=limit
    )
    
    if logs:
        for log in logs:
            timestamp = log.get("timestamp", "Unknown")[:19]
            action = log.get("action_description", "Unknown")
            user = log.get("user", "Unknown")
            
            st.markdown(f"""
            <div style="padding: 0.5rem; border-left: 3px solid #3b82f6; margin: 0.5rem 0; background: #f8fafc;">
                <strong>[{timestamp}]</strong> {action}<br>
                <small>User: {user}</small>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No audit logs found. Audit trail starts recording now.")
    
    # Export option
    if st.button("📥 Export Audit Logs (CSV)"):
        csv_data = export_audit_logs(format="csv")
        st.download_button(
            "Download CSV",
            csv_data,
            file_name="audit_logs.csv",
            mime="text/csv"
        )

# ==========================================
# SCAN HISTORY
# ==========================================
elif audit_page == "📈 Scan History":
    st.title("Scan History")
    
    st.info("Historical record of all security scans")
    
    if history:
        # Display as table
        history_data = []
        for item in history:
            history_data.append({
                "Repository": item.get("repo", "Unknown")[:50],
                "Review Type": item.get("review_type", "N/A"),
                "Risk Score": item.get("risk_score", 0),
                "Timestamp": item.get("timestamp", "Unknown")[:19]
            })
        
        st.dataframe(history_data, use_container_width=True, hide_index=True)
        
        # Statistics
        st.subheader("Statistics")
        
        col1, col2 = st.columns(2)
        
        avg_score = sum(h.get("risk_score", 0) for h in history) / len(history)
        max_score = max(h.get("risk_score", 0) for h in history)
        
        col1.metric("Average Risk Score", round(avg_score, 2))
        col2.metric("Maximum Risk Score", max_score)
    else:
        st.info("No scan history available.")

# ==========================================
# REPORTS ARCHIVE
# ==========================================
elif audit_page == "📄 Reports Archive":
    st.title("Reports Archive")
    
    st.info("Access all generated audit reports")
    
    reports_found = False
    
    for i, review in enumerate(reviews):
        pdf_path = review.get("pdf_path")
        html_path = review.get("html_path")
        
        if pdf_path or html_path:
            reports_found = True
            
            with st.expander(
                f"Report: {review.get('repo', 'Unknown')[:50]} - {review.get('timestamp', 'Unknown')}"
            ):
                col1, col2 = st.columns(2)
                
                if pdf_path:
                    try:
                        with open(pdf_path, "rb") as f:
                            col1.download_button(
                                "📄 Download PDF",
                                f,
                                file_name=f"report_{i}.pdf",
                                mime="application/pdf"
                            )
                    except:
                        col1.write("PDF not available")
                
                if html_path:
                    try:
                        with open(html_path, "rb") as f:
                            col2.download_button(
                                "🌐 Download HTML",
                                f,
                                file_name=f"report_{i}.html",
                                mime="text/html"
                            )
                    except:
                        col2.write("HTML not available")
    
    if not reports_found:
        st.info("No reports available in archive.")

# ==========================================
# INTEGRITY CHECK
# ==========================================
elif audit_page == "✅ Integrity Check":
    st.title("Audit Trail Integrity Check")
    
    st.info("Verify the integrity of the audit trail using cryptographic hashes")
    
    if st.button("🔒 Verify Integrity"):
        with st.spinner("Verifying audit trail integrity..."):
            result = verify_integrity()
            
            if result["valid"]:
                st.success(f"✅ Audit trail is valid! {result['total_entries']} entries verified.")
            else:
                st.error(f"❌ Integrity check failed! {len(result['errors'])} errors found:")
                for error in result["errors"]:
                    st.error(error)
    
    # Show statistics
    logs = get_audit_logs(limit=1000)
    
    if logs:
        st.subheader("Audit Trail Statistics")
        
        col1, col2, col3 = st.columns(3)
        
        col1.metric("Total Entries", len(logs))
        col2.metric("First Entry", logs[-1].get("timestamp", "Unknown")[:10])
        col3.metric("Latest Entry", logs[0].get("timestamp", "Unknown")[:10])
