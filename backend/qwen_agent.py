"""
Qwen AI Gateway (Offline Demo Version)

This version generates deterministic security analysis without
calling OpenRouter or Ollama.
"""

import json


class QwenAgent:

    @staticmethod
    def generate(prompt: str) -> str:
        """
        Offline placeholder.
        """
        return "Offline AI"

    @staticmethod
    def review_finding(finding: dict):

        severity = finding.get("severity", "MEDIUM").upper()
        rule = finding.get("rule", "")
        issue = finding.get("issue", "")

        if "SECRET" in rule.upper():
            owasp = "A02:2021 Cryptographic Failures"
            asvs = "V6"
        elif "AUTH" in rule.upper():
            owasp = "A07:2021 Identification and Authentication Failures"
            asvs = "V2"
        elif "AUTHORIZATION" in rule.upper():
            owasp = "A01:2021 Broken Access Control"
            asvs = "V4"
        elif "DEPENDENCY" in rule.upper():
            owasp = "A06:2021 Vulnerable and Outdated Components"
            asvs = "V14"
        else:
            owasp = "A05:2021 Security Misconfiguration"
            asvs = "V1"

        if severity == "CRITICAL":

            return {
                "risk": "Critical vulnerability detected.",
                "business_impact": "May result in severe business disruption, financial loss, or sensitive data exposure.",
                "technical_impact": "Attackers may fully compromise the application.",
                "owasp": owasp,
                "asvs": asvs,
                "recommendation": "Immediate remediation is required before production deployment.",
                "confidence": 98
            }

        elif severity == "HIGH":

            return {
                "risk": "High-risk security vulnerability.",
                "business_impact": "May significantly affect confidentiality, integrity, or availability.",
                "technical_impact": "Can be exploited under realistic attack scenarios.",
                "owasp": owasp,
                "asvs": asvs,
                "recommendation": "Resolve during the current development cycle.",
                "confidence": 95
            }

        elif severity == "MEDIUM":

            return {
                "risk": "Moderate security weakness.",
                "business_impact": "Could increase operational or compliance risks.",
                "technical_impact": "Weakens the application's overall security posture.",
                "owasp": owasp,
                "asvs": asvs,
                "recommendation": "Fix before production release.",
                "confidence": 90
            }

        else:

            return {
                "risk": "Low-risk security observation.",
                "business_impact": "Minimal business impact.",
                "technical_impact": "Minor security improvement recommended.",
                "owasp": owasp,
                "asvs": asvs,
                "recommendation": "Address during routine maintenance.",
                "confidence": 85
            }

    @staticmethod
    def select_relevant_files(files, review_type):
        """
        Select the first 10 files.
        """
        return files[:10]

    @staticmethod
    def summarize(findings):

        if not findings:
            return "No security findings were detected."

        critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high = sum(1 for f in findings if f.get("severity") == "HIGH")
        medium = sum(1 for f in findings if f.get("severity") == "MEDIUM")
        low = sum(1 for f in findings if f.get("severity") == "LOW")

        return f"""
Repository Security Review Summary

Overall Findings
----------------
Critical : {critical}
High     : {high}
Medium   : {medium}
Low      : {low}

Business Impact
---------------
The repository contains security findings that should be addressed before production deployment. Critical and High severity issues require immediate remediation.

Recommendations
---------------
• Remove hardcoded secrets.
• Validate all user inputs.
• Strengthen authentication and authorization.
• Update vulnerable dependencies.
• Re-run security analysis after remediation.
"""