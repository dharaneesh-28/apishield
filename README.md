# APIShield – Real-Time API Threat Detection & Auto-Response Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/Dashboard-Streamlit-FF4B4B)](https://streamlit.io/)
[![Database](https://img.shields.io/badge/Database-SQLite-003B57)](https://www.sqlite.org/)

APIShield is a real-time API security platform that detects, analyzes, and blocks common web-based threats. The platform monitors incoming API requests, calculates a risk score, stores request activity, and provides automatic threat response through an interactive security dashboard.

## Project Overview

Modern applications receive a large number of API requests every day. Attackers can exploit vulnerable APIs using malicious payloads such as SQL injection, Cross-Site Scripting, and command injection.

APIShield provides a lightweight security monitoring solution that can:

| Capability | Description |
|---|---|
| Request Monitoring | Tracks incoming API requests in real time |
| Threat Detection | Identifies suspicious attack patterns |
| Risk Analysis | Assigns a risk score to each request |
| Automatic Response | Allows, alerts, or blocks requests based on risk |
| Activity Storage | Stores request and threat activity in SQLite |
| Dashboard Visualization | Displays security metrics using Streamlit |
| API Documentation | Provides interactive FastAPI documentation |

## Key Features

| Feature | Description |
|---|---|
| SQL Injection Detection | Detects malicious database query patterns |
| XSS Detection | Identifies suspicious script and HTML payloads |
| Command Injection Detection | Detects operating system command patterns |
| Risk Score Calculation | Calculates a security risk score for each request |
| Threat Blocking | Blocks requests that exceed the configured risk threshold |
| Request Logging | Records request details and security results |
| Security Dashboard | Displays traffic, threats, risk levels, and actions |
| SQLite Integration | Uses a lightweight local database |
| FastAPI Backend | Provides a fast and scalable API server |
| Streamlit UI | Provides an interactive security monitoring interface |

## Technology Stack

| Layer | Technology |
|---|---|
| Programming Language | Python |
| API Framework | FastAPI |
| ASGI Server | Uvicorn |
| Dashboard | Streamlit |
| Database | SQLite |
| Data Processing | Python standard libraries |
| Version Control | Git and GitHub |
| Operating System | Windows, Linux, or macOS |

## System Architecture

```text
Client Request
      |
      v
FastAPI Backend
      |
      v
Request Analyzer
      |
      +--------------------+
      |                    |
      v                    v
Threat Detection      Risk Scoring
      |                    |
      +--------------------+
               |
               v
       Response Decision
               |
       +-------+-------+
       |       |       |
       v       v       v
     Allow   Alert   Block
               |
               v
        SQLite Database
               |
               v
      Streamlit Dashboard
```

## Detection Categories

| Threat Category | Example Description | Default Response |
|---|---|---|
| SQL Injection | Suspicious database query payloads | Block |
| Cross-Site Scripting | Script or HTML injection payloads | Block |
| Command Injection | Operating system command patterns | Block |
| Suspicious Input | Unusual or high-risk request data | Alert |
| Normal Request | Safe API request without malicious patterns | Allow |

## Risk Levels

| Risk Score Range | Risk Level | Recommended Action |
|---|---|---|
| 0–29 | Low | Allow |
| 30–69 | Medium | Alert and monitor |
| 70–100 | High | Block and log |

> Risk thresholds may be adjusted according to the application requirements.

## Project Structure

```text
apishield/
│
├── main.py
├── dashboard.py
├── traffic_sim.py
├── requirements.txt
├── .gitignore
│
├── .streamlit/
│   └── config.toml
│
└── backup_before_dashboard_fix/
    └── Previous project backups
```

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/dharaneesh-28/apishield.git
cd apishield
```

### 2. Create a Virtual Environment

Windows:

```powershell
python -m venv venv
```

Linux or macOS:

```bash
python3 -m venv venv
```

### 3. Activate the Virtual Environment

Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

Windows Command Prompt:

```cmd
venv\Scripts\activate
```

Linux or macOS:

```bash
source venv/bin/activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

If `requirements.txt` is not available, install the main dependencies manually:

```bash
pip install fastapi uvicorn streamlit requests pandas
```

## Running the Application

### Start the FastAPI Backend

```powershell
python -m uvicorn main:app --reload
```

The backend will run at:

```text
http://127.0.0.1:8000
```

### Open API Documentation

FastAPI automatically provides interactive API documentation:

```text
http://127.0.0.1:8000/docs
```

Alternative documentation:

```text
http://127.0.0.1:8000/redoc
```

### Start the Streamlit Dashboard

Open a new terminal window, activate the virtual environment, and run:

```powershell
python -m streamlit run dashboard.py --server.port 8506
```

Open the dashboard:

```text
http://localhost:8506
```

## Testing the Platform

APIShield can be tested using the following request categories:

| Test Type | Purpose |
|---|---|
| Normal Request | Verifies that safe requests are allowed |
| SQL Injection Test | Verifies SQL injection detection |
| XSS Test | Verifies script injection detection |
| Command Injection Test | Verifies command payload detection |
| Large Input Test | Verifies handling of oversized request data |
| Traffic Simulation | Generates sample request activity |

You can also test the API through the interactive Swagger interface:

```text
http://127.0.0.1:8000/docs
```

## Dashboard Metrics

The Streamlit dashboard displays important security information:

| Metric | Purpose |
|---|---|
| Total Requests | Shows the total number of monitored requests |
| Blocked Requests | Shows the number of blocked threats |
| Allowed Requests | Shows safe requests |
| Alert Count | Shows requests requiring attention |
| High-Risk Requests | Shows requests with critical risk scores |
| Average Risk Score | Shows the average security risk |
| Threat Distribution | Displays threat categories |
| Request Timeline | Displays request activity over time |

## Security Workflow

```text
1. Receive an API request
2. Extract request data
3. Scan for malicious patterns
4. Calculate the risk score
5. Classify the request
6. Select an automatic response
7. Store the activity in SQLite
8. Display the result on the dashboard
```

## Database

APIShield uses SQLite to store security activity locally.

Stored information may include:

| Data | Description |
|---|---|
| Request Information | Details related to the incoming request |
| Threat Type | Detected attack category |
| Risk Score | Calculated security score |
| Action | Allow, alert, or block decision |
| Timestamp | Time when the request was processed |
| Analysis Result | Security analysis output |

The database file is intentionally excluded from Git using `.gitignore`.

## Configuration

The Streamlit configuration is stored in:

```text
.streamlit/config.toml
```

Local secrets should be stored in:

```text
.streamlit/secrets.toml
```

Do not upload secrets, passwords, API keys, tokens, or production credentials to GitHub.

## Security Best Practices

| Practice | Recommendation |
|---|---|
| Credentials | Store credentials in environment variables |
| Database | Do not commit local database files |
| Virtual Environment | Keep the `venv` directory ignored |
| API Keys | Never hard-code API keys |
| Passwords | Use secure password hashing in production |
| Deployment | Use HTTPS for production deployments |
| Logging | Avoid storing sensitive request data |
| Authentication | Add secure authentication before deployment |
| Validation | Validate and sanitize all user input |

## Limitations

APIShield is designed for educational, research, and demonstration purposes. It is not a replacement for a complete enterprise Web Application Firewall or production security system.

The following improvements are recommended before production use:

| Area | Required Improvement |
|---|---|
| Authentication | Implement secure user authentication |
| Authorization | Add role-based access control |
| Detection | Use advanced rule and ML-based detection |
| Deployment | Add production-grade server configuration |
| Monitoring | Integrate centralized logging |
| Alerts | Add email, SMS, or webhook notifications |
| Testing | Add automated unit and integration tests |

## Future Enhancements

| Enhancement | Description |
|---|---|
| JWT Authentication | Add token-based API authentication |
| Role-Based Access | Provide admin and analyst roles |
| Machine Learning | Detect unknown attack patterns |
| Email Alerts | Notify administrators about critical threats |
| Webhook Integration | Send events to external systems |
| Docker Support | Containerize the application |
| Cloud Deployment | Deploy on cloud platforms |
| SIEM Integration | Connect with security monitoring tools |
| Report Generation | Generate downloadable security reports |
| Advanced Analytics | Add detailed trend and behavior analysis |

## Use Cases

| Use Case | Description |
|---|---|
| API Security Demonstration | Demonstrates common API threat detection |
| Academic Project | Useful for cybersecurity learning |
| Hackathon Project | Provides a practical security solution |
| Developer Testing | Helps test API input validation |
| Security Monitoring | Displays request and threat activity |
| Research | Supports experimentation with detection rules |

## GitHub Commands

To update the project after making changes:

```powershell
git add .
git commit -m "Update APIShield project"
git push
```

To check the current repository status:

```powershell
git status
```

To check the configured remote:

```powershell
git remote -v
```

## Contribution

Contributions are welcome.

| Step | Action |
|---|---|
| 1 | Fork the repository |
| 2 | Create a new feature branch |
| 3 | Make your changes |
| 4 | Test the changes locally |
| 5 | Commit the changes |
| 6 | Push the branch |
| 7 | Create a pull request |

Example:

```bash
git checkout -b feature/new-security-rule
git add .
git commit -m "Add new security detection rule"
git push origin feature/new-security-rule
```

## License

This project is created for educational, research, hackathon, and demonstration purposes.

## Author

**Dharaneesh K**

GitHub Repository:

```text
https://github.com/dharaneesh-28/apishield
```

## Disclaimer

APIShield is a security research and demonstration project. Always test security tools only on systems and applications that you own or have explicit permission to test.
