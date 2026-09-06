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

def save_log(request, endpoint, input_data, threat_type, risk_score, action):
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
    if data.username == "admin" and data.password == "admin123":
        token = secrets.token_urlsafe(32)
        active_tokens[token] = data.username

return {
            "message": "Login successful",
            "username": data.username,
            "token": token
        }

raise HTTPException(
        status_code=401,
        detail="Invalid username or password"
    )

@app.post("/analyze")
def analyze(data: AnalyzeData, request: Request):
    threat_type, risk_score, action = detect_threat(data.input_text)

save_log(
        request=request,
        endpoint=data.endpoint,
        input_data=data.input_text,
        threat_type=threat_type,
        risk_score=risk_score,
        action=action
    )

if action == "BLOCK":
        return {
            "blocked": True,
            "message": "Threat detected and request blocked",
            "threat_type": threat_type,
            "risk_score": risk_score,
            "action": action
        }

return {
        "blocked": False,
        "message": "Request analyzed successfully",
        "threat_type": threat_type,
        "risk_score": risk_score,
        "action": action
    }

@app.get("/test-injection")
def test_injection(search: str, request: Request):
    threat_type, risk_score, action = detect_threat(search)

save_log(
        request=request,
        endpoint="/test-injection",
        input_data=search,
        threat_type=threat_type,
        risk_score=risk_score,
        action=action
    )

return {
        "input": search,
        "threat_type": threat_type,
        "risk_score": risk_score,
        "action": action,
        "blocked": action == "BLOCK"
    }

@app.get("/logs")
def get_logs(limit: int = 50):
    limit = max(1, min(limit, 200))

connection = get_db()
    rows = connection.execute(
        "SELECT * FROM request_logs ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()
    connection.close()

return {
        "count": len(rows),
        "logs": [dict(row) for row in rows]
    }

@app.get("/stats")
def stats():
    connection = get_db()

total = connection.execute(
        "SELECT COUNT(*) AS count FROM request_logs"
    ).fetchone()["count"]

blocked = connection.execute(
        "SELECT COUNT(*) AS count FROM request_logs WHERE action = 'BLOCK'"
    ).fetchone()["count"]

threats = connection.execute(
        "SELECT COUNT(*) AS count FROM request_logs WHERE threat_type != 'Normal'"
    ).fetchone()["count"]

connection.close()

return {
        "total_requests": total,
        "threats_detected": threats,
        "requests_blocked": blocked,
        "protection_rate": (
            round((blocked / total) * 100, 2) if total else 0
        )
    }
