from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import sqlite3
import secrets
import re
from datetime import datetime, timezone

app = FastAPI(
    title="APIShield",
    description="Real-Time API Threat Detection and Auto-Response Platform",
    version="1.0.0"
)

DB_NAME = "apishield.db"
active_tokens = {}

def get_db():
    connection = sqlite3.connect(DB_NAME)
    connection.row_factory = sqlite3.Row
    return connection

def init_db():
    connection = get_db()
    connection.execute("""
        CREATE TABLE IF NOT EXISTS request_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            method TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            input_data TEXT,
            threat_type TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            action TEXT NOT NULL
        )
    """)
    connection.commit()
    connection.close()

init_db()

class LoginData(BaseModel):
    username: str
    password: str

class AnalyzeData(BaseModel):
    input_text: str
    endpoint: str = "/analyze"

def detect_threat(text: str):
    value = text.lower()

    sql_patterns = [
        "union select",
        "select * from",
        "' or '1'='1",
        "drop table",
        "insert into",
        "delete from",
        "--"
    ]

    xss_patterns = [
        "<script",
        "javascript:",
        "onerror=",
        "onload="
    ]

    command_patterns = [
        "; cat ",
        "; whoami",
        "powershell",
        "cmd.exe",
        "../",
        "..\\"
    ]

    if any(pattern in value for pattern in sql_patterns):
        return "SQL Injection", 95, "BLOCK"

    if any(pattern in value for pattern in xss_patterns):
        return "XSS Attack", 90, "BLOCK"

    if any(pattern in value for pattern in command_patterns):
        return "Command/Path Traversal", 85, "BLOCK"

    if len(text) > 500:
        return "Oversized Input", 60, "ALERT"

    if re.search(r"[<>$`]", text):
        return "Suspicious Input", 40, "MONITOR"

    return "Normal", 0, "ALLOW"


def save_log(request: Request, endpoint: str, input_data: str,
             threat_type: str, risk_score: int, action: str):
    client_ip = request.client.host if request.client else "unknown"

    connection = get_db()
    connection.execute("""
        INSERT INTO request_logs
        (timestamp, endpoint, method, client_ip, input_data,
         threat_type, risk_score, action)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now(timezone.utc).isoformat(),
        endpoint,
        request.method,
        client_ip,
        input_data[:1000],
        threat_type,
        risk_score,
        action
    ))
    connection.commit()
    connection.close()


@app.get("/")
def root():
    return {
        "project": "APIShield",
        "status": "running",
        "flow": "Detect -> Explain -> Block -> Alert -> Review"
    }

@app.get("/health")
def health():
    return {
        "status": "ok",
        "database": "connected"
    }

@app.post("/login")
def login(data: LoginData):
    if data.username != "admin" or data.password != "admin123":
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    token = secrets.token_urlsafe(32)
    active_tokens[token] = data.username

    return {
        "message": "Login successful",
        "username": data.username,
        "token": token
    }

@app.post("/analyze")
def analyze(data: AnalyzeData, request: Request):
    threat_type, risk_score, action = detect_threat(data.input_text)

    save_log(
        request,
        data.endpoint,
        data.input_text,
        threat_type,
        risk_score,
        action
    )

    return {
        "blocked": action == "BLOCK",
        "message": (
            "Threat detected and request blocked"
            if action == "BLOCK"
            else "Request analyzed successfully"
        ),
        "threat_type": threat_type,
        "risk_score": risk_score,
        "action": action
    }

@app.get("/test-injection")
def test_injection(search: str, request: Request):
    threat_type, risk_score, action = detect_threat(search)

    save_log(
        request,
        "/test-injection",
        search,
        threat_type,
        risk_score,
        action
    )

    return {
        "blocked": action == "BLOCK",
        "threat_type": threat_type,
        "risk_score": risk_score,
        "action": action
    }

