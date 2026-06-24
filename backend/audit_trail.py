"""
Audit Trail Module - Immutable logging for ReBIT Security Review Platform
Tracks all security-relevant actions with tamper-evident storage
"""
import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone

AUDIT_FILE = "audit_logs.json"

# Action types for categorization
ACTION_TYPES = {
    "AUTH_LOGIN": "Authentication - Login",
    "AUTH_LOGOUT": "Authentication - Logout",
    "AUTH_REGISTER": "Authentication - Register",
    "SCAN_INITIATE": "Scan - Initiate",
    "SCAN_COMPLETE": "Scan - Complete",
    "SCAN_FAILED": "Scan - Failed",
    "FINDING_CREATE": "Finding - Created",
    "FINDING_UPDATE": "Finding - Status Updated",
    "FINDING_DELETE": "Finding - Deleted",
    "REVIEW_APPROVE": "Review - Approved",
    "REVIEW_REJECT": "Review - Rejected",
    "REVIEW_COMMENT": "Review - Comment Added",
    "REPORT_GENERATE": "Report - Generated",
    "REPORT_DOWNLOAD": "Report - Downloaded",
    "USER_CREATE": "User - Created",
    "USER_UPDATE": "User - Updated",
    "USER_DELETE": "User - Deleted",
    "CONFIG_CHANGE": "Configuration - Changed",
    "DATA_EXPORT": "Data - Exported",
    "ACCESS_DENIED": "Access - Denied",
}


def _compute_hash(entry):
    """Compute SHA-256 hash of an audit entry for integrity verification"""
    data = json.dumps(entry, sort_keys=True)
    return hashlib.sha256(data.encode()).hexdigest()


def _load_audit_logs():
    """Load existing audit logs"""
    if not Path(AUDIT_FILE).exists():
        return []
    
    with open(AUDIT_FILE, "r") as f:
        return json.load(f)


def _save_audit_logs(logs):
    """Save audit logs to file"""
    with open(AUDIT_FILE, "w") as f:
        json.dump(logs, f, indent=2)


def log_action(
    action_type: str,
    user: str,
    details: dict = None,
    ip_address: str = None,
    previous_value: any = None,
    new_value: any = None
):
    """
    Log an action to the audit trail
    
    Args:
        action_type: Type of action (e.g., "SCAN_INITIATE")
        user: Username who performed the action
        details: Additional context about the action
        ip_address: Source IP address (optional)
        previous_value: Previous state (for updates)
        new_value: New state (for updates)
    
    Returns:
        The created audit entry
    """
    logs = _load_audit_logs()
    
    # Get previous hash for chain integrity
    previous_hash = logs[-1]["hash"] if logs else "GENESIS"
    
    timestamp = datetime.now(timezone.utc).isoformat()
    
    entry = {
        "id": len(logs) + 1,
        "timestamp": timestamp,
        "action_type": action_type,
        "action_description": ACTION_TYPES.get(action_type, "Unknown Action"),
        "user": user,
        "details": details or {},
        "ip_address": ip_address,
        "previous_value": previous_value,
        "new_value": new_value,
        "previous_hash": previous_hash,
        "hash": None  # Will be computed after entry is finalized
    }
    
    # Compute hash of this entry (without its own hash)
    entry["hash"] = _compute_hash(entry)
    
    logs.append(entry)
    _save_audit_logs(logs)
    
    return entry


def get_audit_logs(
    user: str = None,
    action_type: str = None,
    start_date: str = None,
    end_date: str = None,
    limit: int = 100
):
    """
    Query audit logs with filters
    
    Args:
        user: Filter by username
        action_type: Filter by action type
        start_date: ISO format start date
        end_date: ISO format end date
        limit: Maximum number of entries to return
    
    Returns:
        List of filtered audit entries
    """
    logs = _load_audit_logs()
    filtered = []
    
    for log in logs:
        # Apply filters
        if user and log["user"] != user:
            continue
        
        if action_type and log["action_type"] != action_type:
            continue
        
        if start_date and log["timestamp"] < start_date:
            continue
        
        if end_date and log["timestamp"] > end_date:
            continue
        
        filtered.append(log)
        
        if len(filtered) >= limit:
            break
    
    # Return most recent first
    return list(reversed(filtered))


def verify_integrity():
    """
    Verify the integrity of the audit trail
    Checks that each entry's hash matches and chain is unbroken
    
    Returns:
        dict with 'valid' boolean and 'errors' list
    """
    logs = _load_audit_logs()
    errors = []
    
    for i, log in enumerate(logs):
        # Verify hash
        expected_hash = log["hash"]
        test_entry = {k: v for k, v in log.items() if k != "hash"}
        actual_hash = _compute_hash(test_entry)
        
        if expected_hash != actual_hash:
            errors.append(f"Entry {i+1}: Hash mismatch")
        
        # Verify chain
        if i > 0:
            expected_prev = logs[i-1]["hash"]
            actual_prev = log["previous_hash"]
            
            if expected_prev != actual_prev:
                errors.append(f"Entry {i+1}: Chain broken")
    
    return {
        "valid": len(errors) == 0,
        "total_entries": len(logs),
        "errors": errors
    }


def export_audit_logs(format: str = "json"):
    """
    Export audit logs for external review
    
    Args:
        format: Export format ('json' or 'csv')
    
    Returns:
        Exported data as string
    """
    logs = _load_audit_logs()
    
    if format == "json":
        return json.dumps(logs, indent=2)
    
    elif format == "csv":
        import csv
        import io
        
        output = io.StringIO()
        fieldnames = [
            "id", "timestamp", "action_type", "action_description",
            "user", "details", "ip_address"
        ]
        
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for log in logs:
            row = {k: log.get(k, "") for k in fieldnames}
            row["details"] = json.dumps(row["details"])
            writer.writerow(row)
        
        return output.getvalue()
    
    return None


def get_user_activity_summary(user: str):
    """
    Get summary of a user's activity
    
    Args:
        user: Username
    
    Returns:
        dict with activity statistics
    """
    logs = get_audit_logs(user=user, limit=1000)
    
    if not logs:
        return {"total_actions": 0}
    
    # Count by action type
    action_counts = {}
    for log in logs:
        action = log["action_type"]
        action_counts[action] = action_counts.get(action, 0) + 1
    
    # Get first and last activity
    first_activity = logs[-1]["timestamp"] if logs else None
    last_activity = logs[0]["timestamp"] if logs else None
    
    return {
        "total_actions": len(logs),
        "action_breakdown": action_counts,
        "first_activity": first_activity,
        "last_activity": last_activity,
        "most_common_action": max(action_counts, key=action_counts.get) if action_counts else None
    }
