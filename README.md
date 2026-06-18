# AI SSDLC Review Assistant

## Overview

AI SSDLC Review Assistant is an intelligent cybersecurity review platform that automates secure code review workflows traditionally performed through Excel-based assessments.

The platform performs repository scanning, risk analysis, security findings generation, AI-assisted reasoning, report generation, and manager approval workflows.

---

## Features

### Developer Portal

* Repository URL Submission
* Input Validation Review
* Authentication Review
* Authorization Review
* Secrets Detection
* Dependency Security Review
* Logging & Monitoring Review
* AI File Selection
* Risk Scoring
* PDF Report Generation
* HTML Report Generation
* Manager Feedback View

### Manager Portal

* Review Queue
* Approve / Reject Reviews
* Manager Comments
* Dashboard Metrics
* Review History

---

## Architecture

Repository Submission

↓

Repository Indexer

↓

AI Reasoning Agent

↓

Security Tools

↓

Findings Engine

↓

Risk Engine

↓

Report Generator

↓

Manager Review Workflow

---

## Tech Stack

Frontend:

* Streamlit

Backend:

* Python

AI:

* Google Gemini / LLM Integration

Security Tools:

* Semgrep
* Custom Static Analysis Rules

Storage:

* JSON-based Persistence

---

## Project Structure

frontend/

* app.py

backend/

* repository_indexer.py
* review_store.py
* auth_store.py
* reasoning_agent.py
* risk_engine.py

users.json
reviews.json

README.md

---

## Workflow

Developer

↓

Submit Repository

↓

Generate Findings

↓

Generate Report

↓

Manager Review

↓

Approve / Reject

↓

Developer Receives Feedback

---

## Future Enhancements

* PostgreSQL Integration
* Role Based Access Control
* OpenAI / OpenRouter Support
* Team Management
* Audit Logging
* Enterprise Dashboard

---

## Author

Rashi Manjrekar
Electronics and Computer Science Engineering
Vidyalankar Institute of Technology
