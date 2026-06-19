"""
Cloud Threat Hunting Console
-----------------------------
A Streamlit dashboard that visualizes the output of detect.py: a world
map tracking where CloudTrail activity originated (highlighting the
impossible-travel path of a simulated compromise), an attack-chain
timeline, and a findings table mapped to MITRE ATT&CK for Cloud.

Run:
    streamlit run dashboard.py
"""

import json
import subprocess
import sys
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

import detect

DATA_DIR = Path(__file__).parent
LOGS_FILE = DATA_DIR / "synthetic_cloudtrail_logs.json"
POSTURE_FILE = DATA_DIR / "posture_findings.json"  # optional, from Guardrail project

AWS_HUB = (40.4173, -82.9071, "AWS us-east-2")

SEVERITY_COLOR = {
    "CRITICAL": "#ff4d4d",
    "HIGH": "#ff9f43",
    "MEDIUM": "#ffd166",
    "BENIGN": "#39d98a",
}

st.set_page_config(
    page_title="Cloud Threat Hunting Console",
    page_icon="◎",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------- THEME ----
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap');

html, body, [class*="css"] { font-family: 'IBM Plex Sans', sans-serif; }
code, .mono { font-family: 'IBM Plex Mono', monospace; }

.stApp {
    background: radial-gradient(ellipse at top, #11151c 0%, #0a0c10 60%);
    color: #e8eaed;
}
section[data-testid="stSidebar"] {
    background: #0d1016;
    border-right: 1px solid #232830;
}
h1, h2, h3 { font-family: 'IBM Plex Sans', sans-serif; letter-spacing: 0.3px; }

.console-header {
    display: flex; justify-content: space-between; align-items: baseline;
    border-bottom: 1px solid #232830; padding-bottom: 14px; margin-bottom: 18px;
}
.console-title { font-size: 1.7rem; font-weight: 700; color: #f1f3f5; }
.console-title span { color: #ffb000; }
.console-sub { font-family: 'IBM Plex Mono', monospace; font-size: 0.8rem; color: #7d8590; }

.hud-frame {
    position: relative; background: #12151b; border: 1px solid #232830;
    border-radius: 6px; padding: 18px 20px; margin-bottom: 16px;
}
.hud-frame::before, .hud-frame::after {
    content: ""; position: absolute; width: 14px; height: 14px;
    border: 2px solid #ffb000; opacity: 0.55;
}
.hud-frame::before { top: -1px; left: -1px; border-right: none; border-bottom: none; }
.hud-frame::after { bottom: -1px; right: -1px; border-left: none; border-top: none; }

.metric-card { text-align: left; }
.metric-label {
    font-family: 'IBM Plex Mono', monospace; font-size: 0.72rem; letter-spacing: 0.08em;
    color: #7d8590; text-transform: uppercase; margin-bottom: 6px;
}
.metric-value { font-size: 2rem; font-weight: 700; color: #f1f3f5; line-height: 1; }
.metric-value.crit { color: #ff4d4d; }
.metric-value.high { color: #ff9f43; }
.metric-value.amber { color: #ffb000; }

.stage-row { display: flex; align-items: flex-start; gap: 14px; margin-bottom: 10px; }
.stage-num {
    font-family: 'IBM Plex Mono', monospace; font-size: 0.75rem; font-weight: 600;
    color: #0a0c10; background: #ffb000; border-radius: 4px; padding: 3px 7px;
    min-width: 26px; text-align: center; margin-top: 2px;
}
.stage-num.crit { background: #ff4d4d; }
.stage-num.high { background: #ff9f43; }
.stage-body { flex: 1; }
.stage-title { font-weight: 600; color: #e8eaed; font-size: 0.92rem; }
.stage-meta { font-family: 'IBM Plex Mono', monospace; font-size: 0.74rem; color: #7d8590; margin-top: 2px; }

.badge {
    font-family: 'IBM Plex Mono', monospace; font-size: 0.7rem; font-weight: 600;
    padding: 2px 7px; border-radius: 3px; display: inline-block;
}
.badge-crit { background: rgba(255,77,77,0.15); color: #ff4d4d; border: 1px solid rgba(255,77,77,0.4); }
.badge-high { background: rgba(255,159,67,0.15); color: #ff9f43; border: 1px solid rgba(255,159,67,0.4); }

table.findings { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
table.findings th {
    text-align: left; font-family: 'IBM Plex Mono', monospace; font-size: 0.7rem;
    text-transform: uppercase; letter-spacing: 0.06em; color: #7d8590;
    border-bottom: 1px solid #232830; padding: 8px 10px;
}
table.findings td { padding: 9px 10px; border-bottom: 1px solid #1a1e25; color: #d6d9de; vertical-align: top; }
table.findings tr:hover td { background: #161a21; }
.tech-id { font-family: 'IBM Plex Mono', monospace; color: #ffb000; }

.empty-state {
    font-family: 'IBM Plex Mono', monospace; color: #7d8590; font-size: 0.85rem;
    border: 1px dashed #2a3038; border-radius: 6px; padding: 16px; text-align: center;
}
</style>
""", unsafe_allow_html=True)


# ------------------------------------------------------------ DATA LOAD ----
@st.cache_data(show_spinner=False)
def load_data(path_str, _nonce=0):
    df = detect.load_events(path_str)
    findings = detect.get_findings(df)
    return df, findings


def load_posture():
    if POSTURE_FILE.exists():
        return json.loads(POSTURE_FILE.read_text())
    return None


# ----------------------------------------------------------- SIDEBAR ----
with st.sidebar:
    st.markdown("### ◎ Console Controls")
    st.caption("Filters and simulation controls")

    severities = st.multiselect(
        "Severity", ["CRITICAL", "HIGH"], default=["CRITICAL", "HIGH"]
    )

    st.divider()
    st.caption("Synthetic data — zero AWS cost")
    if st.button("↻  Regenerate simulation"):
        subprocess.run([sys.executable, str(DATA_DIR / "generate_logs.py")], cwd=DATA_DIR)
        st.cache_data.clear()
        st.rerun()

    uploaded = st.file_uploader("Load a different CloudTrail JSON", type="json")
    if uploaded:
        tmp_path = DATA_DIR / "_uploaded_logs.json"
        tmp_path.write_bytes(uploaded.getvalue())
        active_path = str(tmp_path)
    else:
        active_path = str(LOGS_FILE)

df, findings = load_data(active_path)
findings = [f for f in findings if f["severity"] in severities] if severities else findings

# ------------------------------------------------------------ HEADER ----
st.markdown(f"""
<div class="console-header">
    <div>
        <div class="console-title">SIGNAL <span>//</span> Cloud Threat Hunting Console</div>
        <div class="console-sub">CloudTrail telemetry · MITRE ATT&CK for Cloud · {len(df)} events analyzed</div>
    </div>
    <div class="console-sub">SOURCE: {Path(active_path).name}</div>
</div>
""", unsafe_allow_html=True)

# ------------------------------------------------------------ METRICS ----
crit_n = sum(1 for f in findings if f["severity"] == "CRITICAL")
high_n = sum(1 for f in findings if f["severity"] == "HIGH")
countries = {detect.IP_GEO[ip][2] for ip in df["sourceIPAddress"].unique() if ip in detect.IP_GEO}
users_flagged = {f["user"] for f in findings}

cols = st.columns(5)
metric_data = [
    ("EVENTS ANALYZED", len(df), ""),
    ("FINDINGS", len(findings), "amber"),
    ("CRITICAL", crit_n, "crit"),
    ("HIGH", high_n, "high"),
    ("SOURCE LOCATIONS", len(countries), ""),
]
for col, (label, value, cls) in zip(cols, metric_data):
    col.markdown(f"""
    <div class="hud-frame metric-card">
        <div class="metric-label">{label}</div>
        <div class="metric-value {cls}">{value}</div>
    </div>
    """, unsafe_allow_html=True)

# --------------------------------------------------------------- MAP ----
def build_map(df):
    fig = go.Figure()

    # hub-to-source connectivity (faint, contextual)
    seen_ips = []
    for ip in df["sourceIPAddress"].unique():
        geo = detect.IP_GEO.get(ip)
        if not geo or ip in seen_ips:
            continue
        seen_ips.append(ip)
        is_flagged = ip in df[df["userName"].isin(
            {f["user"] for f in findings}
        )]["sourceIPAddress"].values
        fig.add_trace(go.Scattergeo(
            lon=[geo[1], AWS_HUB[1]], lat=[geo[0], AWS_HUB[0]],
            mode="lines",
            line=dict(width=1, color="rgba(125,133,144,0.35)"),
            hoverinfo="skip", showlegend=False,
        ))

    # the impossible-travel arc, highlighted
    login_geos = []
    logins = df[df["eventName"] == "ConsoleLogin"].sort_values("eventTime")
    for _, row in logins.iterrows():
        geo = detect.IP_GEO.get(row["sourceIPAddress"])
        if geo:
            login_geos.append((geo, row["userName"], row["eventTime"]))

    for i in range(len(login_geos) - 1):
        (g1, u1, t1), (g2, u2, t2) = login_geos[i], login_geos[i + 1]
        if u1 == u2 and g1[2] != g2[2]:
            fig.add_trace(go.Scattergeo(
                lon=[g1[1], g2[1]], lat=[g1[0], g2[0]],
                mode="lines",
                line=dict(width=2.5, color="#ff4d4d"),
                opacity=0.85,
                hoverinfo="text",
                text=f"{u1}: {g1[2]} → {g2[2]} ({(t2-t1)})",
                showlegend=False,
            ))

    # markers per unique location
    plotted = {}
    for ip, geo in detect.IP_GEO.items():
        if ip not in df["sourceIPAddress"].values:
            continue
        flagged = ip in df[df["userName"].isin(
            {f["user"] for f in findings}
        )]["sourceIPAddress"].values and ip == "185.220.101.45"
        plotted[geo[2]] = (geo, flagged)

    fig.add_trace(go.Scattergeo(
        lon=[g[1] for g, _ in plotted.values()],
        lat=[g[0] for g, _ in plotted.values()],
        text=[f"{label}" for label in plotted.keys()],
        mode="markers+text",
        textposition="top center",
        textfont=dict(color="#9aa3ad", size=10, family="IBM Plex Mono"),
        marker=dict(
            size=[14 if flagged else 9 for _, flagged in plotted.values()],
            color=["#ff4d4d" if flagged else "#39d98a" for _, flagged in plotted.values()],
            line=dict(width=1, color="#0a0c10"),
        ),
        hoverinfo="text",
        showlegend=False,
    ))

    # AWS hub marker
    fig.add_trace(go.Scattergeo(
        lon=[AWS_HUB[1]], lat=[AWS_HUB[0]], text=[AWS_HUB[2]],
        mode="markers+text", textposition="bottom center",
        textfont=dict(color="#ffb000", size=10, family="IBM Plex Mono"),
        marker=dict(size=12, color="#ffb000", symbol="diamond",
                    line=dict(width=1, color="#0a0c10")),
        hoverinfo="text", showlegend=False,
    ))

    fig.update_geos(
        projection_type="natural earth",
        bgcolor="rgba(0,0,0,0)",
        landcolor="#181c23",
        oceancolor="#0e1116",
        showocean=True,
        lakecolor="#0e1116",
        coastlinecolor="#2a3038",
        countrycolor="#232830",
        showcountries=True,
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=0, r=0, t=0, b=0),
        height=460,
        font=dict(color="#d6d9de"),
    )
    return fig


st.markdown('<div class="hud-frame">', unsafe_allow_html=True)
st.markdown('<div class="metric-label" style="margin-bottom:10px;">TELEMETRY MAP — SOURCE ORIGIN & SESSION PATH</div>', unsafe_allow_html=True)
st.plotly_chart(build_map(df), use_container_width=True, config={"displayModeBar": False})
st.markdown('</div>', unsafe_allow_html=True)

# ------------------------------------------------------- ATTACK TIMELINE ----
left, right = st.columns([1, 1.4])

with left:
    st.markdown('<div class="hud-frame">', unsafe_allow_html=True)
    st.markdown('<div class="metric-label" style="margin-bottom:10px;">ATTACK CHAIN TIMELINE</div>', unsafe_allow_html=True)
    if findings:
        for i, f in enumerate(findings, start=1):
            cls = "crit" if f["severity"] == "CRITICAL" else "high"
            st.markdown(f"""
            <div class="stage-row">
                <div class="stage-num {cls}">{i:02d}</div>
                <div class="stage-body">
                    <div class="stage-title">{f['technique_name']}</div>
                    <div class="stage-meta">{f['eventTime']} · {f['user']} · <span class="tech-id">{f['technique']}</span></div>
                </div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.markdown('<div class="empty-state">No findings match the current filter. Adjust severity in the sidebar.</div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

with right:
    st.markdown('<div class="hud-frame">', unsafe_allow_html=True)
    st.markdown('<div class="metric-label" style="margin-bottom:10px;">FINDINGS DETAIL</div>', unsafe_allow_html=True)
    if findings:
        rows = "".join(f"""
        <tr>
            <td class="mono">{f['eventTime'][11:19]}</td>
            <td><span class="badge {'badge-crit' if f['severity']=='CRITICAL' else 'badge-high'}">{f['severity']}</span></td>
            <td class="tech-id">{f['technique']}</td>
            <td>{f['user']}</td>
            <td>{f['detail']}</td>
        </tr>""" for f in findings)
        st.markdown(f"""
        <table class="findings">
            <tr><th>Time</th><th>Sev</th><th>Technique</th><th>User</th><th>Detail</th></tr>
            {rows}
        </table>
        """, unsafe_allow_html=True)
    else:
        st.markdown('<div class="empty-state">Nothing to show here yet.</div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

# --------------------------------------------------------- POSTURE PANEL ----
st.markdown('<div class="hud-frame">', unsafe_allow_html=True)
st.markdown('<div class="metric-label" style="margin-bottom:10px;">CLOUD POSTURE FINDINGS (AWS GUARDRAIL)</div>', unsafe_allow_html=True)
posture = load_posture()
if posture:
    rows = "".join(f"""
    <tr>
        <td>{p.get('resource','')}</td>
        <td><span class="badge {'badge-crit' if p.get('severity')=='CRITICAL' else 'badge-high'}">{p.get('severity','')}</span></td>
        <td>{p.get('finding','')}</td>
        <td>{p.get('recommendation','')}</td>
    </tr>""" for p in posture)
    st.markdown(f"""
    <table class="findings">
        <tr><th>Resource</th><th>Sev</th><th>Finding</th><th>Recommendation</th></tr>
        {rows}
    </table>
    """, unsafe_allow_html=True)
else:
    st.markdown("""
    <div class="empty-state">
        No posture scan results loaded. Export your AWS Cloud Guardrail findings to
        <code>posture_findings.json</code> in this folder — schema: a list of objects with
        <code>resource</code>, <code>finding</code>, <code>severity</code>, <code>recommendation</code> —
        and they'll appear here alongside the threat-hunting findings.
    </div>
    """, unsafe_allow_html=True)
st.markdown('</div>', unsafe_allow_html=True)