# ReBIT AI SSDLC Review Platform

Enterprise-grade AI-powered Secure SDLC Review Platform for security assessments.

## 🚀 Features

- **Role-Based Access**: Developer and Manager roles with specific permissions
- **7-Stage Workflow**: Structured review process from intelligence to report
- **Qwen AI Reasoning**: Enterprise-grade vulnerability analysis with OWASP mapping
- **Security Tools**: Integrated Bandit and Semgrep simulation
- **Manager Review Queue**: Approve/reject workflow for completed scans
- **Professional UI**: Modern Streamlit interface with metrics and charts

## 📋 Requirements

- Python 3.8+
- Streamlit

## 🛠️ Installation

```bash
pip install streamlit
```

## 🏃 Running the Application

```bash
streamlit run frontend/app.py
```

The application will start at `http://localhost:8501`

## 👥 Demo Credentials

**Developer:**
- Email: `developer@rebit.com`
- Role: Developer

**Manager:**
- Email: `manager@rebit.com`
- Role: Manager

## 🔄 Application Workflow

1. **Login** → Select role (Developer/Manager)
2. **Dashboard** → View metrics and recent scans
3. **New Scan** (Developer) → Enter repository URL
4. **Progressive Stages**:
   - Repository Intelligence
   - Relevant Files
   - Relevant Functions
   - Code Snippets
   - Security Tool Findings
   - Qwen AI Reasoning
   - Executive Summary
5. **Review Queue** (Manager) → Approve/Reject scans
6. **History** → View past scans and feedback

## 📁 Project Structure

```
/workspace
├── backend/
│   └── workflow_engine.py    # Core workflow logic, AI reasoning, data models
├── frontend/
│   └── app.py                # Streamlit UI
└── README.md
```

## 🔒 Security Features

- **OWASP Top 10 Mapping**: Every finding mapped to OWASP categories
- **ASVS Compliance**: Application Security Verification Standard mapping
- **CWE Identification**: Common Weakness Enumeration codes
- **Risk Scoring**: Automated calculation based on severity
- **Code Traceability**: Direct links from findings to vulnerable code

## 🧪 Testing

Run the backend tests:
```bash
python -c "from backend.workflow_engine import WorkflowManager; print('OK')"
```

## 📊 Dashboard Metrics

- Total Scans
- Completed Reviews
- Average Risk Score
- Critical Findings Count

## 🎯 Key Capabilities

### Developer
- Submit repositories for review
- View real-time scan progress
- Inspect AI findings with code snippets
- Download reports
- View scan history

### Manager
- Access all repository reviews
- Review queue with approve/reject actions
- Team-wide risk analytics
- Provide feedback on scans

## 🤖 Qwen AI Integration

The platform uses a Qwen-style reasoning engine that provides:
- **Why Vulnerable**: Explanation of the security flaw
- **Business Impact**: Potential organizational damage
- **Technical Impact**: System-level consequences
- **Recommendations**: Actionable remediation steps
- **Confidence Scores**: Reliability assessment

## 📝 Example Finding Output

```
CRITICAL: SQL Injection risk
Confidence: 92% | CWE: CWE-89

🧠 AI Reasoning
Why Vulnerable: The code lacks proper input validation...
Business Impact: Could lead to unauthorized access...
Technical Impact: Attackers could execute arbitrary code...

🛡️ OWASP Mapping
Top 10: A03:2021 – Injection
ASVS: V5: Input Validation

✅ Recommendation
Refactor to use parameterized queries...
```

## 🚧 Future Enhancements

- Real GitHub integration
- PDF report generation
- WebSocket real-time updates
- Additional security tools (Gitleaks, pip-audit)
- Jira/Slack integrations

---

**Built for ReBIT Internship Demonstration**
