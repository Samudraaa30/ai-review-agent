"""
Role-Based Access Control (RBAC) Module for ReBIT Security Review Platform
Defines roles, permissions, and access control enforcement
"""

# Role definitions with hierarchy
ROLES = {
    "Developer": {
        "level": 1,
        "description": "Can initiate scans, view own findings, submit reviews",
        "permissions": [
            "scan:initiate",
            "scan:view_own",
            "finding:view_own",
            "finding:comment",
            "report:download_own",
            "review:submit"
        ]
    },
    "Manager": {
        "level": 2,
        "description": "Can approve/reject reviews, view team findings, access dashboards",
        "permissions": [
            "scan:initiate",
            "scan:view_all",
            "finding:view_all",
            "finding:update_status",
            "finding:comment",
            "report:download_all",
            "review:approve",
            "review:reject",
            "review:comment",
            "dashboard:view",
            "audit:view_team"
        ]
    },
    "Auditor": {
        "level": 3,
        "description": "Can view all data, export reports, verify compliance, cannot modify",
        "permissions": [
            "scan:view_all",
            "finding:view_all",
            "finding:export",
            "report:view_all",
            "report:download_all",
            "report:export",
            "audit:view_all",
            "audit:export",
            "compliance:view",
            "history:view_all"
        ]
    },
    "Admin": {
        "level": 4,
        "description": "Full system access including user management and configuration",
        "permissions": [
            "*:*"  # Wildcard - all permissions
        ]
    }
}

# Resource-level access rules
RESOURCE_RULES = {
    "scan": {
        "Developer": ["create", "view_own"],
        "Manager": ["create", "view_all", "cancel"],
        "Auditor": ["view_all"],
        "Admin": ["*"]
    },
    "finding": {
        "Developer": ["view_own", "comment"],
        "Manager": ["view_all", "update_status", "comment"],
        "Auditor": ["view_all", "export"],
        "Admin": ["*"]
    },
    "report": {
        "Developer": ["download_own"],
        "Manager": ["download_all"],
        "Auditor": ["view_all", "download_all", "export"],
        "Admin": ["*"]
    },
    "user": {
        "Developer": [],
        "Manager": ["view_team"],
        "Auditor": [],
        "Admin": ["*"]
    },
    "audit_log": {
        "Developer": [],
        "Manager": ["view_team"],
        "Auditor": ["view_all", "export"],
        "Admin": ["*"]
    },
    "config": {
        "Developer": [],
        "Manager": [],
        "Auditor": [],
        "Admin": ["*"]
    }
}


def get_role_permissions(role: str):
    """
    Get permissions for a specific role
    
    Args:
        role: Role name
    
    Returns:
        List of permission strings
    """
    if role not in ROLES:
        return []
    
    return ROLES[role]["permissions"]


def has_permission(role: str, permission: str):
    """
    Check if a role has a specific permission
    
    Args:
        role: Role name
        permission: Permission string (e.g., "scan:view_all")
    
    Returns:
        Boolean indicating if permission is granted
    """
    if role not in ROLES:
        return False
    
    permissions = ROLES[role]["permissions"]
    
    # Admin wildcard
    if "*:*" in permissions:
        return True
    
    # Direct match
    if permission in permissions:
        return True
    
    # Check resource-level wildcard (e.g., "scan:*")
    resource = permission.split(":")[0]
    if f"{resource}:*" in permissions:
        return True
    
    return False


def can_access_resource(role: str, resource: str, action: str):
    """
    Check if a role can perform an action on a resource
    
    Args:
        role: Role name
        resource: Resource type (scan, finding, report, etc.)
        action: Action (view, create, update, delete, etc.)
    
    Returns:
        Boolean indicating if access is granted
    """
    if role not in RESOURCE_RULES:
        return False
    
    allowed_actions = RESOURCE_RULES[resource].get(role, [])
    
    # Admin wildcard
    if "*" in allowed_actions:
        return True
    
    return action in allowed_actions


def get_role_level(role: str):
    """
    Get the hierarchy level of a role
    
    Args:
        role: Role name
    
    Returns:
        Integer level (higher = more privileges)
    """
    if role not in ROLES:
        return 0
    
    return ROLES[role]["level"]


def can_view_user_data(viewer_role: str, target_role: str):
    """
    Check if a user with viewer_role can view data of user with target_role
    
    Args:
        viewer_role: Role of the user trying to view
        target_role: Role of the target user
    
    Returns:
        Boolean indicating if viewing is allowed
    """
    viewer_level = get_role_level(viewer_role)
    target_level = get_role_level(target_role)
    
    # Can view users at same or lower level
    return viewer_level >= target_level


def enforce_role_requirement(required_role: str, actual_role: str):
    """
    Enforce that a user has at least the required role level
    
    Args:
        required_role: Minimum required role
        actual_role: User's actual role
    
    Returns:
        Boolean indicating if requirement is met
    """
    required_level = get_role_level(required_role)
    actual_level = get_role_level(actual_role)
    
    return actual_level >= required_level


def get_available_roles():
    """
    Get list of all available roles
    
    Returns:
        List of role names
    """
    return list(ROLES.keys())


def get_role_description(role: str):
    """
    Get description of a role
    
    Args:
        role: Role name
    
    Returns:
        Description string
    """
    if role not in ROLES:
        return "Unknown role"
    
    return ROLES[role]["description"]


def validate_role_assignment(assigner_role: str, assignee_role: str):
    """
    Validate if a user can assign a specific role
    
    Users can only assign roles at their level or below
    
    Args:
        assigner_role: Role of user making the assignment
        assignee_role: Role being assigned
    
    Returns:
        Boolean indicating if assignment is valid
    """
    assigner_level = get_role_level(assigner_role)
    assignee_level = get_role_level(assignee_role)
    
    # Can only assign roles at same or lower level
    return assigner_level >= assignee_level


class RBACGuard:
    """
    Context manager for RBAC enforcement
    """
    
    def __init__(self, role: str, required_permission: str):
        self.role = role
        self.permission = required_permission
    
    def __enter__(self):
        if not has_permission(self.role, self.permission):
            raise PermissionError(
                f"Role '{self.role}' does not have permission '{self.permission}'"
            )
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass
    
    @staticmethod
    def check(role: str, permission: str):
        """Static method to check permission"""
        return has_permission(role, permission)
