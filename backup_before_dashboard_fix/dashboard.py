import sqlite3
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

DB_PATH = Path(__file__).resolve().parent / "apishield.db"

st.set_page_config(
    page_title="APIShield Dashboard",
    page_icon="shield",
    layout="wide",
)

st.title("APIShield Security Dashboard")
st.caption("Real-Time API Threat Detection and Auto-Response Platform")

connection = sqlite3.connect(DB_PATH)

logs = pd.read_sql_query(
    """
    SELECT
        id,
        timestamp,
        endpoint,
        method,
        client_ip,
        threat_type,
        risk_score,
        action
    FROM request_logs
    ORDER BY id DESC
    """,
    connection,
)

connection.close()

logs["risk_score"] = pd.to_numeric(
    logs["risk_score"],
    errors="coerce",
).fillna(0)

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Requests", len(logs))
col2.metric("Blocked", int((logs["action"] == "BLOCK").sum()))
col3.metric("Alerts", int((logs["action"] == "ALERT").sum()))
col4.metric("Average Risk", round(float(logs["risk_score"].mean()), 1))

st.subheader("Threat Distribution")

threat_counts = (
    logs["threat_type"]
    .value_counts()
    .rename_axis("Threat")
    .reset_index(name="Count")
)

st.plotly_chart(
    px.bar(threat_counts, x="Threat", y="Count", color="Count"),
    width='stretch',
)

st.subheader("Action Distribution")

action_counts = (
    logs["action"]
    .value_counts()
    .rename_axis("Action")
    .reset_index(name="Count")
)

st.plotly_chart(
    px.pie(
        action_counts,
        names="Action",
        values="Count",
        hole=0.4,
    ),
    width='stretch',
)

st.subheader("Request Logs")
st.dataframe(logs, width='stretch', hide_index=True)

