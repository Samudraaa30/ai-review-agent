"""
Admin Portal - Full system administration for ReBIT Security Review Platform
User management, configuration, and system oversight
"""
import streamlit as st
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from backend.auth_store import (
    load_users, 
    save_users, 
    verify_password,
    create_user,
    update_user_role,
    deactivate_user,
    get_all_users
)
from backend.review_store import load_reviews, save_reviews
from backend.scan_history import load_history
from backend.audit_trail import get_audit_logs, log_action
from backend.rbac import get_available_roles, get_role_description, validate_role_assignment
from datetime import datetime

st.set_page_config(
    page_title="Admin Portal - ReBIT",
    layout="wide",
    page_icon="⚙️"
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
    .user-card {
        background: #f0f9ff;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
    .role-badge {
        padding: 0.25rem 0.75rem;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    .role-admin { background: #dcfce7; color: #16a34a; }
    .role-auditor { background: #fef3c7; color: #d97706; }
    .role-manager { background: #dbeafe; color: #2563eb; }
    .role-developer { background: #f3f4f6; color: #4b5563; }
</style>
""", unsafe_allow_html=True)

# Check authentication
if "logged_in" not in st.session_state or not st.session_state.logged_in:
    st.warning("Please log in to access the Admin Portal")
    st.switch_page("app.py")
    st.stop()

if st.session_state.role != "Admin":
    st.error("Access Denied: This portal is only available to Administrators")
    st.stop()

# Header
st.markdown("""
<div class="rebit-header">
    <h1>⚙️ ReBIT Admin Portal</h1>
    <p style="color: rgba(255,255,255,0.9); margin: 0.5rem 0 0 0;">
        System Administration & User Management
    </p>
</div>
""", unsafe_allow_html=True)

st.sidebar.success(f"Logged in as **{st.session_state.username}** (Administrator)")

# Sidebar navigation
admin_page = st.sidebar.radio(
    "Navigation",
    [
        "👥 User Management",
        "📊 System Overview",
        "🔐 Role Configuration",
        "📜 System Audit Logs",
        "🗄️ Data Management"
    ]
)

if st.sidebar.button("🚪 Logout"):
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.role = None
    st.rerun()

# ==========================================
# USER MANAGEMENT
# ==========================================
if admin_page == "👥 User Management":
    st.title("User Management")
    
    tab1, tab2, tab3 = st.tabs(["📋 User List", "➕ Create User", "✏️ Manage Users"])
    
    # ========== USER LIST ==========
    with tab1:
        st.subheader("All Users")
        
        users = get_all_users()
        
        if users:
            user_data = []
            for user in users:
                role_class = f"role-{user.get('role', 'developer').lower()}"
                user_data.append({
                    "Username": user.get("username"),
                    "Role": user.get("role"),
                    "Status": "✅ Active" if user.get("active", True) else "❌ Inactive",
                    "Created": user.get("created_at", "Unknown")[:10],
                    "Last Login": user.get("last_login", "Never")[:10] if user.get("last_login") else "Never"
                })
            
            st.dataframe(user_data, use_container_width=True, hide_index=True)
        else:
            st.info("No users found.")
    
    # ========== CREATE USER ==========
    with tab2:
        st.subheader("Create New User")
        
        col1, col2 = st.columns(2)
        
        with col1:
            new_username = st.text_input("Username *")
            new_password = st.text_input("Password *", type="password")
            confirm_password = st.text_input("Confirm Password *", type="password")
        
        with col2:
            new_role = st.selectbox(
                "Role *",
                options=get_available_roles(),
                format_func=lambda x: f"{x} - {get_role_description(x)[:50]}"
            )
        
        if st.button("Create User", type="primary"):
            if not new_username or not new_password:
                st.error("Username and password are required")
            elif new_password != confirm_password:
                st.error("Passwords do not match")
            elif len(new_password) < 6:
                st.error("Password must be at least 6 characters")
            else:
                result = create_user(
                    username=new_username,
                    password=new_password,
                    role=new_role,
                    created_by=st.session_state.username
                )
                
                if "error" in result:
                    st.error(result["error"])
                else:
                    st.success(f"User '{new_username}' created successfully with role '{new_role}'")
                    
                    # Log action
                    log_action(
                        action_type="USER_CREATE",
                        user=st.session_state.username,
                        details={
                            "new_user": new_username,
                            "new_role": new_role
                        }
                    )
                    
                    # Clear fields
                    st.rerun()
    
    # ========== MANAGE USERS ==========
    with tab3:
        st.subheader("Manage Existing Users")
        
        users = get_all_users()
        
        if users:
            for user in users:
                with st.expander(f"👤 {user.get('username')} ({user.get('role')})"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write(f"**Status:** {'✅ Active' if user.get('active') else '❌ Inactive'}")
                        st.write(f"**Created:** {user.get('created_at', 'Unknown')}")
                        st.write(f"**Last Login:** {user.get('last_login', 'Never') or 'Never'}")
                    
                    with col2:
                        # Role change (can't change own role)
                        if user.get('username') != st.session_state.username:
                            new_role = st.selectbox(
                                "Change Role",
                                options=get_available_roles(),
                                key=f"role_{user.get('username')}"
                            )
                            
                            if st.button("Update Role", key=f"update_{user.get('username')}"):
                                result = update_user_role(
                                    username=user.get('username'),
                                    new_role=new_role,
                                    updated_by=st.session_state.username
                                )
                                
                                if "error" in result:
                                    st.error(result["error"])
                                else:
                                    st.success(f"Role updated to {new_role}")
                                    
                                    log_action(
                                        action_type="USER_UPDATE",
                                        user=st.session_state.username,
                                        details={
                                            "target_user": user.get('username'),
                                            "old_role": result.get('old_role'),
                                            "new_role": result.get('new_role')
                                        }
                                    )
                        
                        # Deactivate user (can't deactivate self)
                        if user.get('username') != st.session_state.username and user.get('active'):
                            if st.button("Deactivate User", key=f"deactivate_{user.get('username')}"):
                                result = deactivate_user(
                                    username=user.get('username'),
                                    deactivated_by=st.session_state.username
                                )
                                
                                if result.get('success'):
                                    st.success(f"User '{user.get('username')}' deactivated")
                                    
                                    log_action(
                                        action_type="USER_DEACTIVATE",
                                        user=st.session_state.username,
                                        details={"target_user": user.get('username')}
                                    )
                                    st.rerun()

# ==========================================
# SYSTEM OVERVIEW
# ==========================================
elif admin_page == "📊 System Overview":
    st.title("System Overview")
    
    # Load data
    reviews = load_reviews() or []
    history = load_history() or []
    users = get_all_users()
    
    # Key metrics
    col1, col2, col3, col4 = st.columns(4)
    
    col1.metric("Total Users", len(users))
    col2.metric("Total Scans", len(history))
    col3.metric("Total Reviews", len(reviews))
    
    pending = len([r for r in reviews if r.get('status') == 'Pending'])
    col4.metric("Pending Reviews", pending)
    
    # User breakdown by role
    st.subheader("Users by Role")
    
    role_counts = {}
    for user in users:
        role = user.get('role', 'Unknown')
        role_counts[role] = role_counts.get(role, 0) + 1
    
    role_cols = st.columns(len(role_counts))
    for i, (role, count) in enumerate(role_counts.items()):
        role_cols[i].metric(role, count)
    
    # Recent activity
    st.subheader("Recent Activity")
    
    logs = get_audit_logs(limit=10)
    
    if logs:
        for log in logs:
            timestamp = log.get('timestamp', 'Unknown')[:19]
            action = log.get('action_description', 'Unknown')
            user = log.get('user', 'Unknown')
            
            st.markdown(f"`[{timestamp}]` **{action}** by `{user}`")

# ==========================================
# ROLE CONFIGURATION
# ==========================================
elif admin_page == "🔐 Role Configuration":
    st.title("Role Configuration")
    
    st.info("View and understand role permissions in the system")
    
    roles = get_available_roles()
    
    for role in roles:
        with st.expander(f"🎭 {role}"):
            st.write(f"**Description:** {get_role_description(role)}")
            
            # Show permissions (simplified view)
            from backend.rbac import ROLES
            permissions = ROLES.get(role, {}).get('permissions', [])
            
            st.write("**Key Permissions:**")
            for perm in permissions[:10]:  # Show first 10
                st.write(f"- `{perm}`")
            
            if len(permissions) > 10:
                st.write(f"... and {len(permissions) - 10} more")

# ==========================================
# SYSTEM AUDIT LOGS
# ==========================================
elif admin_page == "📜 System Audit Logs":
    st.title("System Audit Logs")
    
    st.info("Complete audit trail of all system actions")
    
    # Filters
    col1, col2, col3 = st.columns(3)
    
    with col1:
        action_filter = st.selectbox(
            "Action Type",
            ["All", "AUTH_LOGIN", "USER_CREATE", "USER_UPDATE", "SCAN_INITIATE", "REVIEW_APPROVE"]
        )
    
    with col2:
        user_filter = st.text_input("Filter by User")
    
    with col3:
        limit = st.slider("Max Entries", 10, 200, 50)
    
    # Get logs
    logs = get_audit_logs(
        action_type=action_filter if action_filter != "All" else None,
        user=user_filter if user_filter else None,
        limit=limit
    )
    
    if logs:
        for log in logs:
            with st.expander(
                f"{log.get('action_description', 'Unknown')} - {log.get('user', 'Unknown')}"
            ):
                st.write(f"**Timestamp:** {log.get('timestamp', 'Unknown')}")
                st.write(f"**User:** {log.get('user', 'Unknown')}")
                st.write(f"**Action:** {log.get('action_type', 'Unknown')}")
                
                if log.get('details'):
                    st.json(log.get('details'))
                
                st.code(f"Hash: {log.get('hash', '')[:32]}...")
    else:
        st.info("No audit logs found.")
    
    # Export
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("📥 Export as JSON"):
            from backend.audit_trail import export_audit_logs
            json_data = export_audit_logs(format="json")
            st.download_button(
                "Download JSON",
                json_data,
                file_name="audit_logs.json",
                mime="application/json"
            )
    
    with col2:
        if st.button("📥 Export as CSV"):
            from backend.audit_trail import export_audit_logs
            csv_data = export_audit_logs(format="csv")
            st.download_button(
                "Download CSV",
                csv_data,
                file_name="audit_logs.csv",
                mime="text/csv"
            )

# ==========================================
# DATA MANAGEMENT
# ==========================================
elif admin_page == "🗄️ Data Management":
    st.title("Data Management")
    
    st.warning("⚠️ These actions affect system data. Proceed with caution.")
    
    tab1, tab2, tab3 = st.tabs(["Reviews", "Scan History", "System"])
    
    with tab1:
        st.subheader("Review Data")
        
        reviews = load_reviews() or []
        
        st.write(f"Total reviews: {len(reviews)}")
        
        if st.button("🗑️ Clear All Reviews"):
            if st.confirm("Are you sure? This cannot be undone."):
                save_reviews([])
                st.success("All reviews cleared")
                log_action(
                    action_type="DATA_CLEAR",
                    user=st.session_state.username,
                    details={"type": "reviews"}
                )
                st.rerun()
    
    with tab2:
        st.subheader("Scan History")
        
        history = load_history() or []
        
        st.write(f"Total scans: {len(history)}")
        
        if st.button("🗑️ Clear Scan History"):
            if st.confirm("Are you sure? This cannot be undone."):
                from backend.scan_history import HISTORY_FILE
                from pathlib import Path
                if Path(HISTORY_FILE).exists():
                    Path(HISTORY_FILE).unlink()
                st.success("Scan history cleared")
                log_action(
                    action_type="DATA_CLEAR",
                    user=st.session_state.username,
                    details={"type": "scan_history"}
                )
                st.rerun()
    
    with tab3:
        st.subheader("System Maintenance")
        
        st.info("System information and maintenance tools")
        
        # Show file sizes
        import os
        
        st.write("**Storage Usage:**")
        
        files_to_check = [
            "users.json",
            "reviews.json",
            "scan_history.json",
            "audit_logs.json"
        ]
        
        for filename in files_to_check:
            try:
                size = os.path.getsize(filename)
                st.write(f"- `{filename}`: {size:,} bytes")
            except:
                st.write(f"- `{filename}`: Not found")
