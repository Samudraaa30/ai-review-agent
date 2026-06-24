import json
import hashlib
from pathlib import Path

FILE = "users.json"

# Default users with bcrypt-hashed passwords (password = username for demo)
# In production, use proper password hashing with bcrypt
DEFAULT_USERS = [
    {
        "username": "admin",
        "password_hash": "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918",  # SHA-256 of "admin"
        "role": "Admin",
        "created_at": "2024-01-01T00:00:00Z",
        "last_login": None,
        "active": True
    },
    {
        "username": "developer",
        "password_hash": "88fa0d759f845b47c044c2cd44e29082cf6fea665c30c146374ec7c8f3d699e3",  # SHA-256 of "developer"
        "role": "Developer",
        "created_at": "2024-01-01T00:00:00Z",
        "last_login": None,
        "active": True
    },
    {
        "username": "manager",
        "password_hash": "6ee4a469cd4e91053847f5d3fcb61dbcc91e8f0ef10be7748da4c4a1ba382d17",  # SHA-256 of "manager"
        "role": "Manager",
        "created_at": "2024-01-01T00:00:00Z",
        "last_login": None,
        "active": True
    },
    {
        "username": "auditor",
        "password_hash": "c5a62ce3fa7f6d86af0009389ccd815277691ea64da0c5c98e302bb13dd59248",  # SHA-256 of "auditor"
        "role": "Auditor",
        "created_at": "2024-01-01T00:00:00Z",
        "last_login": None,
        "active": True
    }
]


def _hash_password(password: str) -> str:
    """Hash password using SHA-256 (use bcrypt in production)"""
    return hashlib.sha256(password.encode()).hexdigest()


def _migrate_users(users):
    """Migrate plain text passwords to hashed passwords"""
    migrated = []
    for user in users:
        new_user = user.copy()
        
        # If has plain password, convert to hash
        if "password" in new_user and "password_hash" not in new_user:
            new_user["password_hash"] = _hash_password(new_user["password"])
            del new_user["password"]
        
        # Add missing fields
        if "role" not in new_user:
            new_user["role"] = "Developer"
        if "created_at" not in new_user:
            new_user["created_at"] = "2024-01-01T00:00:00Z"
        if "last_login" not in new_user:
            new_user["last_login"] = None
        if "active" not in new_user:
            new_user["active"] = True
        
        migrated.append(new_user)
    
    return migrated


def load_users():
    """Load users from file, migrate if needed, ensure defaults exist"""
    
    if not Path(FILE).exists():
        # Create default users file
        save_users(DEFAULT_USERS)
        return DEFAULT_USERS.copy()
    
    with open(FILE, "r") as f:
        users = json.load(f)
    
    # Migrate if needed
    if users and "password" in users[0]:
        users = _migrate_users(users)
        save_users(users)
    
    # Ensure all default roles exist
    existing_roles = {u["role"] for u in users}
    required_roles = ["Admin", "Developer", "Manager", "Auditor"]
    
    for role in required_roles:
        if role not in existing_roles:
            # Find default user for this role
            for default in DEFAULT_USERS:
                if default["role"] == role:
                    users.append(default.copy())
                    break
    
    return users


def save_users(users):
    """Save users to file"""
    with open(FILE, "w") as f:
        json.dump(users, f, indent=4)


def verify_password(username: str, password: str) -> dict:
    """
    Verify user credentials
    
    Args:
        username: Username to verify
        password: Plain text password
    
    Returns:
        User dict if valid, None otherwise
    """
    users = load_users()
    
    password_hash = _hash_password(password)
    
    for user in users:
        if (user.get("username") == username and 
            user.get("password_hash") == password_hash and
            user.get("active", True)):
            
            # Update last login
            from datetime import datetime, timezone
            user["last_login"] = datetime.now(timezone.utc).isoformat()
            save_users(users)
            
            return {
                "username": user["username"],
                "role": user["role"],
                "active": user.get("active", True)
            }
    
    return None


def create_user(username: str, password: str, role: str, created_by: str = None) -> dict:
    """
    Create a new user
    
    Args:
        username: New username
        password: Plain text password
        role: User role
        created_by: Username of creator (for audit)
    
    Returns:
        Created user dict or error dict
    """
    from datetime import datetime, timezone
    
    users = load_users()
    
    # Check if user exists
    for user in users:
        if user.get("username") == username:
            return {"error": "Username already exists"}
    
    # Validate role
    from .rbac import get_available_roles
    if role not in get_available_roles():
        return {"error": "Invalid role"}
    
    new_user = {
        "username": username,
        "password_hash": _hash_password(password),
        "role": role,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_login": None,
        "active": True,
        "created_by": created_by
    }
    
    users.append(new_user)
    save_users(users)
    
    return {
        "username": new_user["username"],
        "role": new_user["role"],
        "created_at": new_user["created_at"]
    }


def update_user_role(username: str, new_role: str, updated_by: str = None) -> dict:
    """
    Update user's role
    
    Args:
        username: Username to update
        new_role: New role
        updated_by: Username of updater (for audit)
    
    Returns:
        Updated user dict or error dict
    """
    users = load_users()
    
    for user in users:
        if user.get("username") == username:
            old_role = user.get("role")
            user["role"] = new_role
            
            # Log update info
            user["updated_by"] = updated_by
            user["updated_at"] = str(datetime.now(timezone.utc))
            
            save_users(users)
            
            return {
                "username": user["username"],
                "old_role": old_role,
                "new_role": new_role
            }
    
    return {"error": "User not found"}


def deactivate_user(username: str, deactivated_by: str = None) -> dict:
    """
    Deactivate a user
    
    Args:
        username: Username to deactivate
        deactivated_by: Username of deactivator (for audit)
    
    Returns:
        Success dict or error dict
    """
    from datetime import datetime, timezone
    
    users = load_users()
    
    for user in users:
        if user.get("username") == username:
            user["active"] = False
            user["deactivated_by"] = deactivated_by
            user["deactivated_at"] = datetime.now(timezone.utc).isoformat()
            
            save_users(users)
            
            return {"success": True, "username": username}
    
    return {"error": "User not found"}


def get_all_users():
    """Get all users (without password hashes)"""
    users = load_users()
    
    return [
        {
            "username": u.get("username"),
            "role": u.get("role"),
            "active": u.get("active", True),
            "created_at": u.get("created_at"),
            "last_login": u.get("last_login")
        }
        for u in users
    ]