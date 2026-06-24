"""
Finding Filters Module for ReBIT Security Review Platform
Provides filtering, sorting, and search capabilities for security findings
"""

from typing import List, Dict, Optional


# Severity levels with numeric values for sorting
SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0
}

# Status options for findings
STATUS_OPTIONS = [
    "Open",
    "In Progress",
    "False Positive",
    "Fixed",
    "Won't Fix",
    "Accepted Risk"
]

# Review types
REVIEW_TYPES = [
    "Input Validation",
    "Whitelisting Review",
    "Secrets Detection",
    "Authentication Review",
    "Authorization Review",
    "Dependency Security",
    "Logging & Monitoring"
]


def filter_findings(
    findings: List[Dict],
    severity: Optional[str] = None,
    review_type: Optional[str] = None,
    status: Optional[str] = None,
    file_pattern: Optional[str] = None,
    min_severity: Optional[str] = None
) -> List[Dict]:
    """
    Filter findings by various criteria
    
    Args:
        findings: List of finding dictionaries
        severity: Filter by exact severity (CRITICAL, HIGH, MEDIUM, LOW)
        review_type: Filter by review type
        status: Filter by status (Open, Fixed, etc.)
        file_pattern: Filter by file path pattern (substring match)
        min_severity: Filter by minimum severity level
    
    Returns:
        Filtered list of findings
    """
    filtered = findings.copy()
    
    # Filter by exact severity
    if severity:
        filtered = [f for f in filtered if f.get("severity") == severity]
    
    # Filter by minimum severity
    if min_severity:
        min_level = SEVERITY_ORDER.get(min_severity, 0)
        filtered = [
            f for f in filtered 
            if SEVERITY_ORDER.get(f.get("severity", "INFO"), 0) >= min_level
        ]
    
    # Filter by review type
    if review_type:
        filtered = [f for f in filtered if f.get("review_type") == review_type]
    
    # Filter by status
    if status:
        filtered = [f for f in filtered if f.get("status") == status]
    
    # Filter by file pattern
    if file_pattern:
        filtered = [
            f for f in filtered 
            if file_pattern.lower() in f.get("file", "").lower()
        ]
    
    return filtered


def sort_findings(
    findings: List[Dict],
    sort_by: str = "severity",
    reverse: bool = True
) -> List[Dict]:
    """
    Sort findings by various criteria
    
    Args:
        findings: List of finding dictionaries
        sort_by: Field to sort by (severity, file, line, review_type, status)
        reverse: Sort in descending order (default True for severity)
    
    Returns:
        Sorted list of findings
    """
    if not findings:
        return findings
    
    if sort_by == "severity":
        return sorted(
            findings,
            key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO"), 0),
            reverse=True
        )
    
    elif sort_by == "file":
        return sorted(findings, key=lambda x: x.get("file", ""), reverse=reverse)
    
    elif sort_by == "line":
        return sorted(
            findings,
            key=lambda x: int(x.get("line", 0)),
            reverse=reverse
        )
    
    elif sort_by == "review_type":
        return sorted(
            findings,
            key=lambda x: x.get("review_type", ""),
            reverse=reverse
        )
    
    elif sort_by == "status":
        return sorted(
            findings,
            key=lambda x: x.get("status", ""),
            reverse=reverse
        )
    
    return findings


def search_findings(
    findings: List[Dict],
    query: str,
    search_fields: Optional[List[str]] = None
) -> List[Dict]:
    """
    Search findings by text query
    
    Args:
        findings: List of finding dictionaries
        query: Search query string
        search_fields: Fields to search in (default: issue, recommendation, file, code)
    
    Returns:
        List of matching findings
    """
    if not query:
        return findings
    
    if search_fields is None:
        search_fields = ["issue", "recommendation", "file", "code"]
    
    query_lower = query.lower()
    matched = []
    
    for finding in findings:
        for field in search_fields:
            value = str(finding.get(field, ""))
            if query_lower in value.lower():
                matched.append(finding)
                break
    
    return matched


def get_filter_options(findings: List[Dict]) -> Dict:
    """
    Get available filter options based on current findings
    
    Args:
        findings: List of finding dictionaries
    
    Returns:
        Dictionary with available options for each filter
    """
    severities = set()
    review_types = set()
    statuses = set()
    files = set()
    
    for finding in findings:
        if finding.get("severity"):
            severities.add(finding["severity"])
        if finding.get("review_type"):
            review_types.add(finding["review_type"])
        if finding.get("status"):
            statuses.add(finding["status"])
        if finding.get("file"):
            files.add(finding["file"])
    
    return {
        "severities": sorted(
            list(severities),
            key=lambda x: SEVERITY_ORDER.get(x, 0),
            reverse=True
        ),
        "review_types": sorted(list(review_types)),
        "statuses": sorted(list(statuses)),
        "files": sorted(list(files))
    }


def get_severity_summary(findings: List[Dict]) -> Dict:
    """
    Get count of findings by severity
    
    Args:
        findings: List of finding dictionaries
    
    Returns:
        Dictionary with severity counts
    """
    summary = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
        "total": len(findings)
    }
    
    for finding in findings:
        severity = finding.get("severity", "INFO")
        if severity in summary:
            summary[severity] += 1
    
    return summary


def get_status_summary(findings: List[Dict]) -> Dict:
    """
    Get count of findings by status
    
    Args:
        findings: List of finding dictionaries
    
    Returns:
        Dictionary with status counts
    """
    summary = {}
    
    for finding in findings:
        status = finding.get("status", "Open")
        summary[status] = summary.get(status, 0) + 1
    
    return summary


def get_review_type_summary(findings: List[Dict]) -> Dict:
    """
    Get count of findings by review type
    
    Args:
        findings: List of finding dictionaries
    
    Returns:
        Dictionary with review type counts
    """
    summary = {}
    
    for finding in findings:
        review_type = finding.get("review_type", "Unknown")
        summary[review_type] = summary.get(review_type, 0) + 1
    
    return summary


def paginate_findings(
    findings: List[Dict],
    page: int = 1,
    page_size: int = 20
) -> Dict:
    """
    Paginate findings for display
    
    Args:
        findings: List of finding dictionaries
        page: Page number (1-indexed)
        page_size: Number of items per page
    
    Returns:
        Dictionary with paginated results and metadata
    """
    total = len(findings)
    total_pages = (total + page_size - 1) // page_size
    
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    
    return {
        "items": findings[start_idx:end_idx],
        "page": page,
        "page_size": page_size,
        "total_items": total,
        "total_pages": total_pages,
        "has_next": page < total_pages,
        "has_prev": page > 1
    }


def apply_filters_and_sort(
    findings: List[Dict],
    filters: Dict,
    sort_by: str = "severity",
    sort_reverse: bool = True,
    page: int = 1,
    page_size: int = 20
) -> Dict:
    """
    Apply all filters, sorting, and pagination in one call
    
    Args:
        findings: List of finding dictionaries
        filters: Dictionary of filter values
        sort_by: Field to sort by
        sort_reverse: Sort direction
        page: Page number
        page_size: Items per page
    
    Returns:
        Dictionary with filtered, sorted, paginated results
    """
    # Apply filters
    filtered = filter_findings(
        findings,
        severity=filters.get("severity"),
        review_type=filters.get("review_type"),
        status=filters.get("status"),
        file_pattern=filters.get("file_pattern"),
        min_severity=filters.get("min_severity")
    )
    
    # Apply search
    if filters.get("search_query"):
        filtered = search_findings(filtered, filters["search_query"])
    
    # Sort
    sorted_findings = sort_findings(filtered, sort_by, sort_reverse)
    
    # Paginate
    paginated = paginate_findings(sorted_findings, page, page_size)
    
    # Add summaries
    paginated["severity_summary"] = get_severity_summary(filtered)
    paginated["status_summary"] = get_status_summary(filtered)
    paginated["filter_options"] = get_filter_options(filtered)
    
    return paginated
