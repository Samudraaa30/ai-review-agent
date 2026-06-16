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

st.set_page_config(
    page_title="AI SSDLC Review Agent",
    layout="wide"
)

st.title("🔒 AI SSDLC Review Agent")

repo_url = st.text_input(
    "GitHub Repository URL"
)

review_type = st.selectbox(
    "Review Type",
    [
        "Input Validation",
        "Secrets Detection",
        "Authentication Review",
        "Authorization Review"
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

            files = discover_files(
                repo_path
            )

            ast_results = analyze_python_ast(
                repo_path
            )
            java_ast_results = analyze_java(
                repo_path
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
            st.success(
                "Input Validation Review Complete"
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
            st.metric(
                "Repository Risk Score",
                f"{risk_score}/100"
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