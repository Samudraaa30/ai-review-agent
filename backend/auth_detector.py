from pathlib import Path

AUTH_PATTERNS = [
    "JWT",
    "Bearer",
    "Authentication",
    "Authorization",
    "Password",
    "PasswordEncoder",
    "BCrypt",
    "UserDetails",
    "UserDetailsService",
    "SecurityContext",
    "Principal",
    "Login",
    "login",
    "Session",
    "session",
    "Token",
    "token",
    "@PreAuthorize",
    "@RolesAllowed",
    "hasRole(",
    "hasAuthority(",
    "authorizeRequests(",
    "AuthenticationManager"
]
def detect_auth(repo_path):

    findings = []

    for file in Path(repo_path).rglob("*"):

        if file.suffix not in [
            ".java",
            ".js",
            ".ts",
            ".py"
        ]:
            continue

        try:

            lines = file.read_text(
                encoding="utf-8",
                errors="ignore"
            ).splitlines()

            for line_num, line in enumerate(
                lines,
                start=1
            ):

                for pattern in AUTH_PATTERNS:

                    if pattern in line:

                        findings.append(
                            {
                                "file": str(file),
                                "line": line_num,
                                "type": pattern,
                                "code": line.strip()
                            }
                        )

        except Exception:
            pass

    return findings