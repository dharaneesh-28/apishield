import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

# ── Config ────────────────────────────────────────────────────────────────────
DB_PATH = Path(__file__).resolve().parent / "apishield.db"

st.set_page_config(
    page_title="APIShield – Security Overview",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Session state ─────────────────────────────────────────────────────────────
if "page"             not in st.session_state: st.session_state.page             = "Overview"
if "prev_ids"         not in st.session_state: st.session_state.prev_ids         = set()
if "new_count"        not in st.session_state: st.session_state.new_count        = 0
if "last_refresh"     not in st.session_state: st.session_state.last_refresh     = datetime.now(timezone.utc)
if "refresh_interval" not in st.session_state: st.session_state.refresh_interval = 5
if "auto_refresh"     not in st.session_state: st.session_state.auto_refresh     = True
if "prev_total"       not in st.session_state: st.session_state.prev_total       = 0
if "snapshot_ids"     not in st.session_state: st.session_state.snapshot_ids     = set()
if "snapshot_total"   not in st.session_state: st.session_state.snapshot_total   = 0

# ── Load fresh data every rerun (no caching) ─────────────────────────────────
def load_data():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query(
        "SELECT id, timestamp, endpoint, method, client_ip, threat_type, risk_score, action "
        "FROM request_logs ORDER BY id DESC",
        conn,
    )
    conn.close()
    df["risk_score"] = pd.to_numeric(df["risk_score"], errors="coerce").fillna(0)
    return df

logs        = load_data()
current_ids = set(logs["id"].tolist())

# Compare with SNAPSHOT from previous cycle (set at end of last render)
new_ids     = current_ids - st.session_state.snapshot_ids
delta_total = len(logs) - st.session_state.snapshot_total
st.session_state.new_count   = len(new_ids)
st.session_state.last_refresh = datetime.now(timezone.utc)

total        = len(logs)
blocked      = int((logs["action"] == "BLOCK").sum())
alerts_n     = int((logs["action"] == "ALERT").sum())
avg_risk     = round(float(logs["risk_score"].mean()), 1) if total > 0 else 0.0
block_pct    = f"{round(blocked/total*100,1)}% of traffic" if total > 0 else "—"

threat_logs  = logs[logs["threat_type"].notna() & ~logs["threat_type"].isin(["Normal",""])].copy()
threat_counts = threat_logs["threat_type"].value_counts().reset_index()
threat_counts.columns = ["Threat","Count"]
action_counts = logs["action"].value_counts().reset_index()
action_counts.columns = ["Action","Count"]

THREAT_COLORS = ["#e8a020","#d45050","#5090d4","#5ab080","#9060d0","#c07030"]
ACTION_COLORS = {"BLOCK":"#d45050","ALERT":"#e8c040","ALLOW":"#4caf50","MONITOR":"#5090d4"}

# ── CSS ────────────────────────────────────────────────────────────────────────
ri = st.session_state.refresh_interval
st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
html,body,[class*="css"]{{font-family:'Inter',sans-serif;}}
#MainMenu,footer,header{{visibility:hidden;}}

section[data-testid="stSidebar"]{{
    background:#1a1208!important; border-right:1px solid #2e2010;
    min-width:210px!important; max-width:210px!important;
}}
section[data-testid="stSidebar"] * {{color:#c8b89a!important;}}
section[data-testid="stSidebar"] > div{{
    display:flex;flex-direction:column;height:100vh;padding-bottom:0!important;
}}
section[data-testid="stSidebar"] > div > .stMarkdown:last-child{{margin-top:auto!important;}}

.sidebar-brand{{display:flex;align-items:center;gap:10px;padding:18px 16px 6px 16px;font-weight:700;font-size:17px;color:#f0e0c0!important;}}
.brand-icon{{background:#e8a020;color:#1a1208!important;border-radius:8px;width:32px;height:32px;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:13px;flex-shrink:0;}}
.nav-sep{{margin:8px 16px 10px 16px;height:1px;background:#2e2010;}}

/* ── sidebar nav buttons ── */
section[data-testid="stSidebar"] .stButton > button {{
    width:100%!important;
    background:transparent!important;
    border:none!important;
    border-radius:6px!important;
    color:#c8b89a!important;
    font-size:13px!important;
    font-family:'Inter',sans-serif!important;
    text-align:left!important;
    padding:9px 16px!important;
    margin:1px 0!important;
    cursor:pointer!important;
    box-shadow:none!important;
    transition:background 0.15s!important;
}}
section[data-testid="stSidebar"] .stButton > button:hover {{
    background:#261c08!important;
    color:#f0e0c0!important;
}}
section[data-testid="stSidebar"] .stButton > button:focus {{
    box-shadow:none!important;
    outline:none!important;
    border:none!important;
}}
/* active nav button — we add a data attr via a wrapper div */
.nav-active > .stButton > button {{
    background:#2e2010!important;
    color:#f0e0c0!important;
    font-weight:600!important;
}}
.nav-badge{{
    display:inline-block;background:#3a1a0a;border:1px solid #5a3010;
    color:#e8a020;font-size:9px;font-weight:700;
    padding:1px 6px;border-radius:10px;margin-left:6px;
}}

.user-footer{{
    padding:14px 16px 20px 16px;border-top:1px solid #2e2010;
    display:flex;align-items:center;gap:10px;
}}
.user-avatar{{
    width:28px;height:28px;border-radius:50%;
    background:#3a2a10;border:1px solid #5a4020;
    display:flex;align-items:center;justify-content:center;
    font-size:11px;font-weight:700;color:#e8a020!important;flex-shrink:0;
}}
.user-name{{font-size:12px;font-weight:600;color:#c8b89a!important;line-height:1.2;}}
.user-ver{{font-size:10px;color:#7a6a50!important;}}

.block-container{{background:#1e1508!important;padding:0!important;max-width:100%!important;}}

.topbar{{
    display:flex;align-items:center;background:#1a1208;border-bottom:1px solid #2e2010;
    padding:14px 28px;gap:16px;flex-wrap:wrap;
}}
.topbar-title{{font-size:20px;font-weight:700;color:#f0e0c0;}}
.topbar-status{{
    display:flex;align-items:center;gap:6px;
    background:#1e2a1a;border:1px solid #2a4022;
    border-radius:20px;padding:4px 12px;font-size:12px;color:#6fbf6f;
}}
.dot-green{{width:7px;height:7px;border-radius:50%;background:#4caf50;display:inline-block;animation:pulse 2s infinite;}}
@keyframes pulse{{0%,100%{{box-shadow:0 0 0 2px rgba(76,175,80,0.25);}}50%{{box-shadow:0 0 0 5px rgba(76,175,80,0.08);}}}}
.topbar-time{{font-size:12px;color:#8a7a60;margin-left:auto;}}

.live-bar-wrap{{
    background:#1a1208;border-bottom:2px solid #2e2010;
    padding:0 28px;display:flex;align-items:center;gap:14px;height:32px;
}}
.live-label{{font-size:11px;color:#7a6a50;white-space:nowrap;display:flex;align-items:center;gap:5px;}}
.live-dot{{width:6px;height:6px;border-radius:50%;background:#4caf50;animation:pulse 1.5s infinite;display:inline-block;}}
.live-bar-track{{flex:1;height:4px;background:#2e2010;border-radius:2px;overflow:hidden;}}
.live-bar-fill{{
    height:4px;border-radius:2px;
    background:linear-gradient(90deg,#e8a020,#4caf50);
    animation:countdown {ri}s linear forwards;
}}
@keyframes countdown{{from{{width:100%;}}to{{width:0%;}}}}
.live-next{{font-size:11px;color:#7a6a50;white-space:nowrap;}}

.new-banner{{
    background:#1a2a10;border:1px solid #3a6020;border-radius:8px;
    padding:10px 18px;margin:12px 28px 0 28px;font-size:12px;color:#6fbf6f;
    display:flex;align-items:center;gap:10px;animation:fadeInDown 0.4s ease;
}}
@keyframes fadeInDown{{from{{opacity:0;transform:translateY(-8px);}}to{{opacity:1;transform:translateY(0);}}}}

.section-heading{{font-size:18px;font-weight:700;color:#f0e0c0;padding:18px 28px 4px 28px;}}
.page-wrap{{padding:0 28px 40px 28px;}}

.metrics-row{{display:flex;gap:14px;padding:8px 28px 24px 28px;}}
.metric-card{{
    flex:1;background:#241a0a;border:1px solid #2e2010;
    border-radius:10px;padding:18px 22px;min-width:0;transition:border-color 0.4s,box-shadow 0.4s;
}}
.metric-card.flash{{border-color:#4caf50;box-shadow:0 0 16px rgba(76,175,80,0.2);}}
.metric-label{{font-size:11px;color:#8a7a60;text-transform:uppercase;letter-spacing:0.8px;margin-bottom:6px;}}
.metric-value{{font-size:34px;font-weight:700;color:#f0e0c0;line-height:1.1;}}
.metric-value.orange{{color:#e8a020;}}
.metric-value.red{{color:#e05050;}}
.metric-delta-up{{font-size:11px;color:#4caf50;margin-top:4px;}}
.metric-delta-dn{{font-size:11px;color:#e05050;margin-top:4px;}}
.metric-sub{{font-size:11px;color:#8a7a60;margin-top:4px;}}

.dist-card{{background:#241a0a;border:1px solid #2e2010;border-radius:10px;padding:18px 22px;height:100%;}}
.dist-title{{font-size:14px;font-weight:600;color:#f0e0c0;margin-bottom:2px;}}
.dist-sub{{font-size:11px;color:#7a6a50;margin-bottom:10px;}}

.card{{background:#241a0a;border:1px solid #2e2010;border-radius:10px;padding:20px 24px;margin-bottom:14px;}}
.card-title{{font-size:14px;font-weight:600;color:#f0e0c0;margin-bottom:6px;}}
.card-sub{{font-size:12px;color:#7a6a50;}}

.flag-banner{{
    background:#2a2005;border:1px solid #5a4010;border-radius:8px;padding:12px 18px;
    margin:18px 28px;font-size:12px;color:#c8a840;display:flex;gap:10px;align-items:flex-start;
}}
.flag-link{{color:#e8c040;font-weight:600;}}

.logs-section{{padding:4px 28px 40px 28px;}}
.logs-title{{font-size:16px;font-weight:700;color:#f0e0c0;margin-bottom:2px;}}
.logs-sub{{font-size:12px;color:#7a6a50;margin-bottom:14px;}}

table.req-table{{width:100%;border-collapse:collapse;font-size:12px;color:#c8b89a;}}
table.req-table thead tr{{border-bottom:1px solid #2e2010;}}
table.req-table thead th{{
    color:#7a6a50;font-weight:600;letter-spacing:0.6px;
    text-transform:uppercase;font-size:10.5px;padding:8px 10px;text-align:left;
}}
table.req-table tbody tr{{border-bottom:1px solid #221808;transition:background 0.2s;}}
table.req-table tbody tr:hover{{background:#2a1e0a;}}
table.req-table tbody td{{padding:9px 10px;vertical-align:middle;}}
table.req-table td.ep{{color:#e8a020;font-family:monospace;font-size:11.5px;}}
table.req-table tbody tr.new-row{{animation:rowFlash 3s ease forwards;}}
@keyframes rowFlash{{0%{{background:#1e3a10;}}70%{{background:#1a2a10;}}100%{{background:transparent;}}}}

.risk-wrap{{display:flex;align-items:center;gap:8px;}}
.risk-bar-bg{{flex:1;height:5px;background:#2e2010;border-radius:3px;overflow:hidden;}}
.risk-bar-fill{{height:5px;border-radius:3px;}}
.risk-val{{font-size:12px;color:#e8dcc8;width:24px;text-align:right;flex-shrink:0;}}

.badge{{display:inline-block;border-radius:4px;font-size:10.5px;font-weight:700;padding:2px 9px;letter-spacing:0.5px;}}
.badge-block  {{background:#4a0a0a;color:#ff6060;border:1px solid #7a1010;}}
.badge-alert  {{background:#3a2a00;color:#e8c040;border:1px solid #5a4010;}}
.badge-allow  {{background:#0a2a0a;color:#4caf50;border:1px solid #1a4a1a;}}
.badge-monitor{{background:#0a1a3a;color:#60a0e8;border:1px solid #1a3060;}}
.badge-new    {{background:#1a3a10;color:#6fbf6f;border:1px solid #3a6020;font-size:9px;padding:1px 5px;margin-right:4px;vertical-align:middle;}}

.logs-footer{{font-size:11px;color:#7a6a50;display:flex;justify-content:space-between;margin-top:10px;}}
.blink{{animation:blink 1.2s step-start infinite;}}
@keyframes blink{{50%{{opacity:0;}}}}

.setting-row{{display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid #221808;font-size:13px;color:#c8b89a;}}
.setting-key{{color:#8a7a60;font-size:11px;font-family:monospace;}}
.policy-rule{{font-family:monospace;font-size:11px;color:#e8a020;margin:2px 0;}}

/* search/filter inputs */
section[data-testid="stMain"] input{{
    background:#241a0a!important;border:1px solid #3a2a10!important;
    color:#e8dcc8!important;border-radius:6px!important;font-size:12px!important;
}}
section[data-testid="stMain"] .stSelectbox>div{{
    background:#241a0a!important;border:1px solid #3a2a10!important;
    color:#e8dcc8!important;border-radius:6px!important;
}}
</style>
""", unsafe_allow_html=True)

# ── Helpers ───────────────────────────────────────────────────────────────────



def rbadge(action):
    cls = {"BLOCK":"badge-block","ALERT":"badge-alert","ALLOW":"badge-allow","MONITOR":"badge-monitor"}.get(action,"badge-monitor")
    return f'<span class="badge {cls}">{action}</span>'

def risk_bar(score):
    pct = min(int(score), 100)
    color = "#e05050" if pct>=75 else ("#e8a020" if pct>=50 else "#4caf50")
    return (f'<div class="risk-wrap"><div class="risk-bar-bg">'
            f'<div class="risk-bar-fill" style="width:{pct}%;background:{color};"></div>'
            f'</div><span class="risk-val">{int(score)}</span></div>')

def fmt_ts(raw):
    try:
        dt = datetime.fromisoformat(str(raw).replace("Z","+00:00"))
        return dt.strftime("%H:%M:%S")
    except Exception:
        return str(raw)[:8]

def donut_fig(labels, values, colors, center):
    fig = go.Figure(go.Pie(labels=labels, values=values, hole=0.55,
        marker=dict(colors=colors, line=dict(color="#1a1208", width=2)),
        textinfo="none"))
    fig.update_layout(showlegend=False, margin=dict(l=0,r=0,t=0,b=0), height=190,
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        annotations=[dict(text=center, x=0.5, y=0.5, font_size=17,
                          showarrow=False, font_color="#f0e0c0")])
    return fig

def legend_html(items, colors, counts, total_n):
    rows=""
    for i,(label,cnt) in enumerate(zip(items,counts)):
        pct = round(cnt/total_n*100,1) if total_n>0 else 0
        c = colors[i%len(colors)] if isinstance(colors,list) else colors.get(label,"#888")
        rows += (f'<tr><td style="padding:3px 8px 3px 0;">'
                 f'<span style="display:inline-block;width:10px;height:10px;border-radius:2px;'
                 f'background:{c};margin-right:5px;vertical-align:middle;"></span>{label}</td>'
                 f'<td style="text-align:right;color:#c8b89a;font-weight:600;padding-left:10px;">'
                 f'{cnt} · {pct}%</td></tr>')
    return f'<table style="font-size:12px;color:#c8b89a;width:100%;margin-top:16px;">{rows}</table>'

def build_table(df, show_new=True, limit=None):
    rows=""
    src = df.head(limit) if limit else df
    for _, row in src.iterrows():
        threat  = row["threat_type"] if row["threat_type"] not in ("Normal",None,"") else "—"
        is_new  = show_new and row["id"] in new_ids
        cls     = "new-row" if is_new else ""
        tag     = '<span class="badge badge-new">NEW</span>' if is_new else ""
        rows   += (f'<tr class="{cls}"><td>{fmt_ts(row["timestamp"])}</td>'
                   f'<td class="ep">{tag}{row["endpoint"]}</td>'
                   f'<td>{row["client_ip"]}</td>'
                   f'<td>{"—" if threat=="—" else threat}</td>'
                   f'<td>{risk_bar(row["risk_score"])}</td>'
                   f'<td>{rbadge(row["action"])}</td></tr>')
    if not rows:
        rows = '<tr><td colspan="6" style="text-align:center;padding:24px;color:#7a6a50;">No matching records</td></tr>'
    return rows

# ── NAV config ────────────────────────────────────────────────────────────────
NAV_PAGES = [
    ("Overview",     "⊞"),
    ("Threats",      "⚠"),
    ("Request Logs", "≡"),
    ("Policies",     "⛊"),
    ("Settings",     "⚙"),
]
NAV_BADGES = {"Threats": len(threat_logs), "Request Logs": total}

# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
        <div class="sidebar-brand">
            <div class="brand-icon">AS</div>
            <div>APIShield
                <div style="font-size:9px;font-weight:400;color:#7a6a50;margin-top:1px;">ENTERPRISE</div>
            </div>
        </div>
        <div class="nav-sep"></div>
    """, unsafe_allow_html=True)

    for p, emoji in NAV_PAGES:
        active = st.session_state.page == p
        badge  = f'  [{NAV_BADGES[p]}]' if p in NAV_BADGES else ''
        label  = f'{"▶ " if active else "   "}{emoji}  {p}{badge}'
        # wrap in div so we can target active with CSS class
        wrap_cls = "nav-active" if active else "nav-inactive"
        st.markdown(f'<div class="{wrap_cls}">', unsafe_allow_html=True)
        if st.button(label, key=f"nav_{p}", use_container_width=True):
            st.session_state.page = p
            st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div style="flex:1;min-height:20px;"></div>', unsafe_allow_html=True)
    st.markdown("""
        <div class="user-footer">
            <div class="user-avatar">DK</div>
            <div>
                <div class="user-name">Dharaneesh K</div>
                <div class="user-ver">Sep 5, 2026 · v1.0</div>
            </div>
        </div>
    """, unsafe_allow_html=True)

# ── Shared top bar ─────────────────────────────────────────────────────────────
_now     = datetime.now(timezone.utc)
now_str  = f"{_now.strftime('%b')} {_now.day}, {_now.strftime('%Y · %H:%M:%S UTC')}"
titles   = {"Overview":"Security Overview","Threats":"Threat Analysis",
            "Request Logs":"Request Logs","Policies":"Detection Policies","Settings":"Settings"}

st.markdown(f"""
<div class="topbar">
    <span class="topbar-title">{titles[st.session_state.page]}</span>
    <span class="topbar-status"><span class="dot-green"></span>&nbsp;Live Monitoring</span>
    <span class="topbar-time">Updated {now_str}</span>
</div>
""", unsafe_allow_html=True)

# Live bar (only on live pages)
live_pages = ("Overview","Threats","Request Logs")
if st.session_state.auto_refresh and st.session_state.page in live_pages:
    st.markdown(f"""
    <div class="live-bar-wrap">
        <span class="live-label"><span class="live-dot"></span>&nbsp;LIVE</span>
        <div class="live-bar-track"><div class="live-bar-fill"></div></div>
        <span class="live-next">Auto-refresh in {st.session_state.refresh_interval}s</span>
    </div>
    """, unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# PAGE ▸ OVERVIEW
# ══════════════════════════════════════════════════════════════════════════════
if st.session_state.page == "Overview":

    if st.session_state.new_count > 0:
        st.markdown(f"""
        <div class="new-banner">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#6fbf6f" stroke-width="2.5">
                <polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/>
                <polyline points="17 6 23 6 23 12"/>
            </svg>
            <strong>{st.session_state.new_count} new request{"s" if st.session_state.new_count!=1 else ""}</strong>
            &nbsp;arrived since last cycle — rows highlighted below ↓
        </div>""", unsafe_allow_html=True)

    flash = "flash" if st.session_state.new_count > 0 else ""

    # delta labels
    def delta_html(val, suffix=""):
        if val > 0: return f'<div class="metric-delta-up">▲ +{val}{suffix}</div>'
        if val < 0: return f'<div class="metric-delta-dn">▼ {val}{suffix}</div>'
        return f'<div class="metric-sub">No change this cycle</div>'

    st.markdown("<div class='section-heading'>Live metrics — last 24 hours</div>", unsafe_allow_html=True)
    st.markdown(f"""
    <div class="metrics-row">
        <div class="metric-card {flash}">
            <div class="metric-label">Total Requests</div>
            <div class="metric-value">{total}</div>
            {delta_html(delta_total, " requests")}
        </div>
        <div class="metric-card {flash}">
            <div class="metric-label">Blocked</div>
            <div class="metric-value">{blocked}</div>
            <div class="metric-sub">{block_pct}</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Alerts</div>
            <div class="metric-value">{alerts_n}</div>
            <div class="metric-sub">{"Active" if alerts_n>0 else "None"} · ALERT actions</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Avg Risk Score</div>
            <div class="metric-value orange">{avg_risk}</div>
            <div class="metric-sub">{"⚠ Elevated" if avg_risk>=50 else "✓ Normal"} · threshold 50</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<div class='section-heading' style='padding-bottom:12px;'>Distribution breakdown</div>", unsafe_allow_html=True)
    cl, cr = st.columns(2)

    with cl:
        st.markdown('<div class="dist-card"><div class="dist-title">Threat Distribution</div>'
                    '<div class="dist-sub">Classified threat types across requests</div>', unsafe_allow_html=True)
        if not threat_counts.empty:
            tt = threat_counts["Count"].sum()
            c1,c2 = st.columns([1,1.2])
            with c1: st.plotly_chart(donut_fig(threat_counts["Threat"].tolist(), threat_counts["Count"].tolist(),
                THREAT_COLORS, f"<b>{tt}</b><br><span style='font-size:11px'>threats</span>"),
                width="stretch", config={"displayModeBar":False})
            with c2: st.markdown(legend_html(threat_counts["Threat"], THREAT_COLORS, threat_counts["Count"], tt), unsafe_allow_html=True)
        else: st.info("No threat data yet.")
        st.markdown("</div>", unsafe_allow_html=True)

    with cr:
        st.markdown('<div class="dist-card"><div class="dist-title">Action Distribution</div>'
                    '<div class="dist-sub">Enforcement actions taken on requests</div>', unsafe_allow_html=True)
        if not action_counts.empty:
            at = action_counts["Count"].sum()
            a_colors = [ACTION_COLORS.get(a,"#888") for a in action_counts["Action"]]
            c1,c2 = st.columns([1,1.2])
            with c1: st.plotly_chart(donut_fig(action_counts["Action"].tolist(), action_counts["Count"].tolist(),
                a_colors, f"<b>{at}</b><br><span style='font-size:11px'>actions</span>"),
                width="stretch", config={"displayModeBar":False})
            with c2: st.markdown(legend_html(action_counts["Action"], ACTION_COLORS, action_counts["Count"], at), unsafe_allow_html=True)
        else: st.info("No action data yet.")
        st.markdown("</div>", unsafe_allow_html=True)

    action_total = int(action_counts["Count"].sum()) if not action_counts.empty else 0
    if action_total > total > 0:
        ratio = round(action_total/total*100,1)
        st.markdown(f"""<div class="flag-banner">
            <span style="font-size:15px;flex-shrink:0;">⚠</span>
            <span><span class="flag-link">Validation flag:</span>
            action totals ({action_total}) exceed {total} logged requests —
            {ratio}% action-to-request ratio. One request likely triggered a dual action. Reconcile before export.</span>
        </div>""", unsafe_allow_html=True)

    _lr  = st.session_state.last_refresh
    lr_s = f"{_lr.strftime('%b')} {_lr.day} · {_lr.strftime('%H:%M:%S UTC')}"
    rows = build_table(logs, show_new=True, limit=10)
    st.markdown(f"""
    <div class="logs-section">
        <div class="logs-title">
            Request Logs
            <span style="font-size:11px;color:#4caf50;font-weight:400;margin-left:10px;">
                <span class="blink">●</span> Live · refreshed {lr_s}
            </span>
        </div>
        <div class="logs-sub">Last 10 requests · auto-updating every {st.session_state.refresh_interval}s</div>
        <table class="req-table">
            <thead><tr><th>TIMESTAMP</th><th>ENDPOINT</th><th>SOURCE IP</th>
            <th>THREAT CLASS</th><th>RISK SCORE</th><th>ACTION</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
        <div class="logs-footer">
            <span>Showing 10 of {total} requests · window: last 24h</span>
            <span>Avg risk {avg_risk} · Owner Dharaneesh K · Sep 5, 2026</span>
        </div>
    </div>""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# PAGE ▸ THREATS
# ══════════════════════════════════════════════════════════════════════════════
elif st.session_state.page == "Threats":

    high_risk = threat_logs[threat_logs["risk_score"] >= 75]
    med_risk  = threat_logs[(threat_logs["risk_score"] >= 50) & (threat_logs["risk_score"] < 75)]

    st.markdown(f"""
    <div class="metrics-row">
        <div class="metric-card">
            <div class="metric-label">Total Threats</div>
            <div class="metric-value red">{len(threat_logs)}</div>
            <div class="metric-sub">Across all categories</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Critical (≥ 75)</div>
            <div class="metric-value red">{len(high_risk)}</div>
            <div class="metric-sub">Immediate attention</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Medium (50–74)</div>
            <div class="metric-value orange">{len(med_risk)}</div>
            <div class="metric-sub">Monitor closely</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Unique Types</div>
            <div class="metric-value">{threat_counts["Threat"].nunique() if not threat_counts.empty else 0}</div>
            <div class="metric-sub">Distinct threat classes</div>
        </div>
    </div>""", unsafe_allow_html=True)

    cl, cr = st.columns(2)
    with cl:
        st.markdown('<div class="dist-card"><div class="dist-title">Threat Breakdown</div>'
                    '<div class="dist-sub">Distribution by type</div>', unsafe_allow_html=True)
        if not threat_counts.empty:
            tt = threat_counts["Count"].sum()
            c1,c2 = st.columns([1,1.2])
            with c1: st.plotly_chart(donut_fig(threat_counts["Threat"].tolist(), threat_counts["Count"].tolist(),
                THREAT_COLORS, f"<b>{tt}</b><br><span style='font-size:11px'>threats</span>"),
                width="stretch", config={"displayModeBar":False})
            with c2: st.markdown(legend_html(threat_counts["Threat"], THREAT_COLORS, threat_counts["Count"], tt), unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with cr:
        st.markdown('<div class="dist-card"><div class="dist-title">Risk Score Distribution</div>'
                    '<div class="dist-sub">Severity spread across threat events</div>', unsafe_allow_html=True)
        if not threat_logs.empty:
            bins   = [0,25,50,75,100]
            labels_b = ["Low\n0–25","Med\n25–50","High\n50–75","Crit\n75–100"]
            threat_logs["band"] = pd.cut(threat_logs["risk_score"], bins=bins, labels=labels_b, include_lowest=True)
            bc = threat_logs["band"].value_counts().reindex(labels_b, fill_value=0)
            fig_bar = go.Figure(go.Bar(x=bc.index.tolist(), y=bc.values.tolist(),
                marker_color=["#4caf50","#e8c040","#e8a020","#e05050"], marker_line_width=0))
            fig_bar.update_layout(margin=dict(l=0,r=0,t=0,b=0), height=190,
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#c8b89a",size=11),
                xaxis=dict(gridcolor="#2e2010",zeroline=False),
                yaxis=dict(gridcolor="#2e2010",zeroline=False))
            st.plotly_chart(fig_bar, width="stretch", config={"displayModeBar":False})
        st.markdown("</div>", unsafe_allow_html=True)

    rows = build_table(threat_logs, show_new=True)
    st.markdown(f"""
    <div class="logs-section">
        <div class="logs-title">Threat Events <span style="font-size:11px;color:#4caf50;font-weight:400;margin-left:8px;"><span class="blink">●</span> Live</span></div>
        <div class="logs-sub">Only flagged requests · {len(threat_logs)} of {total} total</div>
        <table class="req-table">
            <thead><tr><th>TIMESTAMP</th><th>ENDPOINT</th><th>SOURCE IP</th>
            <th>THREAT CLASS</th><th>RISK SCORE</th><th>ACTION</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
    </div>""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# PAGE ▸ REQUEST LOGS
# ══════════════════════════════════════════════════════════════════════════════
elif st.session_state.page == "Request Logs":

    st.markdown("<div style='padding:14px 28px 4px 28px;'>", unsafe_allow_html=True)
    cf1, cf2, cf3 = st.columns([2, 1.2, 1.2])
    with cf1:
        search = st.text_input("Search", placeholder="🔍  Search endpoint or IP…", label_visibility="collapsed")
    with cf2:
        act_f  = st.selectbox("Action Filter", ["All Actions","BLOCK","ALERT","ALLOW","MONITOR"], label_visibility="collapsed")
    with cf3:
        thr_f  = st.selectbox("Threat Filter", ["All Threats"] + (threat_counts["Threat"].tolist() if not threat_counts.empty else []), label_visibility="collapsed")
    st.markdown("</div>", unsafe_allow_html=True)

    filtered = logs.copy()
    if search:
        filtered = filtered[
            filtered["endpoint"].str.contains(search, case=False, na=False) |
            filtered["client_ip"].str.contains(search, case=False, na=False)
        ]
    if act_f != "All Actions":
        filtered = filtered[filtered["action"] == act_f]
    if thr_f != "All Threats":
        filtered = filtered[filtered["threat_type"] == thr_f]

    is_filtered = search or act_f != "All Actions" or thr_f != "All Threats"
    _lr  = st.session_state.last_refresh
    rows = build_table(filtered, show_new=True)
    st.markdown(f"""
    <div class="logs-section">
        <div class="logs-title">
            All Requests
            <span style="font-size:11px;color:#4caf50;font-weight:400;margin-left:10px;">
                <span class="blink">●</span> Live · {_lr.strftime('%H:%M:%S UTC')}
            </span>
        </div>
        <div class="logs-sub">
            {len(filtered)} result{"s" if len(filtered)!=1 else ""}
            {" · filtered" if is_filtered else " · all records"} ·
            auto-refresh every {st.session_state.refresh_interval}s
        </div>
        <table class="req-table">
            <thead><tr><th>TIMESTAMP</th><th>ENDPOINT</th><th>SOURCE IP</th>
            <th>THREAT CLASS</th><th>RISK SCORE</th><th>ACTION</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
        <div class="logs-footer">
            <span>Showing {len(filtered)} of {total} requests</span>
            <span>Avg risk {avg_risk} · Dharaneesh K</span>
        </div>
    </div>""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# PAGE ▸ POLICIES
# ══════════════════════════════════════════════════════════════════════════════
elif st.session_state.page == "Policies":

    st.markdown("<div class='section-heading'>Active Detection Policies</div>", unsafe_allow_html=True)
    st.markdown("<div class='page-wrap'>", unsafe_allow_html=True)

    policies = [
        {"name":"SQL Injection Detection","desc":"Detects common SQL injection patterns in request payloads",
         "rules":["union select","select * from","' or '1'='1","drop table","insert into","delete from","--"],
         "action":"BLOCK","risk":95,"color":"#d45050"},
        {"name":"XSS Attack Detection","desc":"Identifies Cross-Site Scripting attempts in input fields",
         "rules":["<script","javascript:","onerror=","onload="],
         "action":"BLOCK","risk":90,"color":"#d45050"},
        {"name":"Command / Path Traversal","desc":"Catches command injection and directory traversal attempts",
         "rules":["; cat ","; whoami","powershell","cmd.exe","../","..\\"],
         "action":"BLOCK","risk":85,"color":"#e8a020"},
        {"name":"Oversized Input","desc":"Flags requests with unusually large payloads (> 500 chars)",
         "rules":["len(text) > 500"],
         "action":"ALERT","risk":60,"color":"#e8c040"},
        {"name":"Suspicious Characters","desc":"Monitors inputs containing special shell/script characters",
         "rules":["<", ">", "$", "`"],
         "action":"MONITOR","risk":40,"color":"#5090d4"},
    ]

    for pol in policies:
        ac = {"BLOCK":"badge-block","ALERT":"badge-alert","MONITOR":"badge-monitor"}.get(pol["action"],"badge-monitor")
        rules_html = "".join(f'<div class="policy-rule">&nbsp;·&nbsp; {r}</div>' for r in pol["rules"])
        st.markdown(f"""
        <div class="card">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px;">
                <div>
                    <div class="card-title" style="color:{pol['color']};">{pol['name']}</div>
                    <div class="card-sub">{pol['desc']}</div>
                </div>
                <div style="text-align:right;flex-shrink:0;margin-left:20px;">
                    <span class="badge {ac}">{pol['action']}</span><br>
                    <span style="font-size:10px;color:#7a6a50;margin-top:4px;display:block;">Risk: {pol['risk']}</span>
                </div>
            </div>
            <div style="padding:10px 12px;background:#1a1208;border-radius:6px;border:1px solid #2e2010;">
                <div style="font-size:10px;color:#7a6a50;margin-bottom:6px;letter-spacing:0.5px;">MATCH PATTERNS</div>
                {rules_html}
            </div>
        </div>""", unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# PAGE ▸ SETTINGS
# ══════════════════════════════════════════════════════════════════════════════
elif st.session_state.page == "Settings":

    st.markdown("<div class='section-heading'>Settings</div>", unsafe_allow_html=True)
    st.markdown("<div class='page-wrap'>", unsafe_allow_html=True)
    cs1, cs2 = st.columns(2)

    with cs1:
        st.markdown('<div class="card"><div class="card-title">Auto-Refresh</div>', unsafe_allow_html=True)
        auto = st.toggle("Enable auto-refresh", value=st.session_state.auto_refresh, key="tog_auto")
        if auto != st.session_state.auto_refresh:
            st.session_state.auto_refresh = auto
            st.rerun()
        interval = st.select_slider("Refresh interval (seconds)",
            options=[5,8,10,15,30,60], value=st.session_state.refresh_interval, key="sl_int")
        if interval != st.session_state.refresh_interval:
            st.session_state.refresh_interval = interval
            st.rerun()
        on_off = "#4caf50" if st.session_state.auto_refresh else "#e05050"
        st.markdown(f'<div style="margin-top:10px;font-size:12px;color:#7a6a50;">'
                    f'Status: <strong style="color:{on_off};">{"ON" if st.session_state.auto_refresh else "OFF"}</strong>'
                    f' · Interval: <strong style="color:#e8a020;">{st.session_state.refresh_interval}s</strong></div>',
                    unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown('<div class="card" style="margin-top:14px;"><div class="card-title">Database</div>', unsafe_allow_html=True)
        db_size = round(DB_PATH.stat().st_size/1024, 1)
        st.markdown(f"""
        <div class="setting-row"><span>File</span><span class="setting-key">{DB_PATH.name}</span></div>
        <div class="setting-row"><span>Total Records</span><span style="color:#e8a020;font-weight:600;">{total}</span></div>
        <div class="setting-row"><span>Size</span><span class="setting-key">{db_size} KB</span></div>
        <div class="setting-row"><span>Threats Logged</span><span style="color:#d45050;font-weight:600;">{len(threat_logs)}</span></div>
        """, unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with cs2:
        st.markdown('<div class="card"><div class="card-title">Detection Thresholds</div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="setting-row"><span>SQL Injection</span><span style="color:#e05050;font-weight:600;">Risk 95 → BLOCK</span></div>
        <div class="setting-row"><span>XSS Attack</span><span style="color:#e05050;font-weight:600;">Risk 90 → BLOCK</span></div>
        <div class="setting-row"><span>Path Traversal</span><span style="color:#e8a020;font-weight:600;">Risk 85 → BLOCK</span></div>
        <div class="setting-row"><span>Oversized Input</span><span style="color:#e8c040;font-weight:600;">Risk 60 → ALERT</span></div>
        <div class="setting-row"><span>Suspicious Input</span><span style="color:#5090d4;font-weight:600;">Risk 40 → MONITOR</span></div>
        <div class="setting-row"><span>Alert threshold</span><span style="color:#e8a020;font-weight:600;">50</span></div>
        """, unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown('<div class="card" style="margin-top:14px;"><div class="card-title">System Info</div>', unsafe_allow_html=True)
        st.markdown(f"""
        <div class="setting-row"><span>Version</span><span class="setting-key">v1.0.0</span></div>
        <div class="setting-row"><span>Owner</span><span style="color:#c8b89a;">Dharaneesh K</span></div>
        <div class="setting-row"><span>Environment</span><span style="color:#4caf50;font-weight:600;">Production</span></div>
        <div class="setting-row"><span>API Status</span><span style="color:#4caf50;font-weight:600;">● Operational</span></div>
        <div class="setting-row"><span>Last Refresh</span><span class="setting-key">{st.session_state.last_refresh.strftime('%H:%M:%S UTC')}</span></div>
        """, unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)

# ── Snapshot current state BEFORE sleeping (so next cycle detects delta) ──────
st.session_state.snapshot_ids   = current_ids
st.session_state.snapshot_total = len(logs)

# ── Auto-refresh ──────────────────────────────────────────────────────────────
if st.session_state.auto_refresh and st.session_state.page in live_pages:
    time.sleep(st.session_state.refresh_interval)
    st.rerun()
