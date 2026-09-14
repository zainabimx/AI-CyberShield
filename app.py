import re
import sqlite3
from datetime import datetime
from urllib.parse import urlparse
from pathlib import Path

import joblib
import pandas as pd
import streamlit as st

from src.database import (
    delete_alert,
    delete_old_closed_alerts,
    get_alert,
    get_all_alerts,
    save_alert,
    update_alert_status,
    save_incident_report,
    get_incident_report,
    update_incident_report,
    get_all_incident_reports,
    get_database_stats,
    clear_all_soc_data,
)
from src.security_core import create_alert, extract_iocs, severity_from_score
from src.analyst_notes import get_analyst_notes, save_analyst_notes, delete_analyst_notes
from llm import generate_threat_analysis, generate_website_analysis
from report_generator import generate_incident_report, update_incident_report_content
from pdf_generator import create_incident_pdf


# -----------------------------------------------------------------------------
# APPLICATION CONFIGURATION
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="AI CyberShield | SOC",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)


# -----------------------------------------------------------------------------
# DESIGN SYSTEM
# -----------------------------------------------------------------------------
st.markdown(
    """
<style>
:root {
    --bg: #0a0f14;
    --sidebar: #080d12;
    --surface: #0f161e;
    --surface-2: #121b24;
    --surface-3: #0c131a;
    --line: #202c38;
    --line-soft: #17222d;
    --text: #e7edf3;
    --muted: #82909e;
    --dim: #5d6b78;
    --accent: #4bb7c4;
    --accent-soft: #15333a;
    --critical: #ed6570;
    --high: #e39a54;
    --medium: #d4b35c;
    --low: #6fa4db;
    --success: #65b993;
}

html, body, [class*="css"] {
    font-family: Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont,
                 "Segoe UI", sans-serif;
}

.stApp {
    background: var(--bg);
    color: var(--text);
}

[data-testid="stHeader"] { background: transparent; }
[data-testid="stToolbar"] { visibility: visible; }
[data-testid="stDecoration"] { display: none; }

/* Keep the native sidebar toggle easy to find after collapsing navigation. */
[data-testid="stSidebarCollapseButton"] {
    display: flex !important;
    visibility: visible !important;
    opacity: 1 !important;
    z-index: 999999 !important;
}
[data-testid="stSidebarCollapseButton"] button {
    min-width: 36px !important;
    min-height: 36px !important;
    border: 1px solid #2b3d49 !important;
    background: #101922 !important;
    color: #c8d4dc !important;
    border-radius: 5px !important;
}
[data-testid="stSidebarCollapseButton"] button:hover {
    background: #17242e !important;
    border-color: #4b7b84 !important;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background: var(--sidebar) !important;
    overflow:hidden !important;
    border-right: 1px solid var(--line-soft);
}
[data-testid="stSidebar"] > div:first-child { padding: 20px 14px; }
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p { margin: 0; }
[data-testid="stSidebar"] div[role="radiogroup"] { gap: 3px; }
[data-testid="stSidebar"] div[role="radiogroup"] label {
    border: 1px solid transparent !important;
    border-radius: 4px !important;
    background: transparent !important;
    color: #84929f !important;
    min-height: 36px;
    padding: 7px 9px !important;
    transition: background .12s ease, color .12s ease, border .12s ease;
}
[data-testid="stSidebar"] div[role="radiogroup"] label:hover {
    background: #101821 !important;
    color: #dce5ec !important;
}
[data-testid="stSidebar"] div[role="radiogroup"] label[data-checked="true"] {
    background: #10252b !important;
    border-color: #24464e !important;
    color: #79cbd4 !important;
    box-shadow: inset 2px 0 0 var(--accent);
}
[data-testid="stSidebar"] label [data-testid="stWidgetSelectedIndicator"] { display: none; }

.brand {
    color: #f2f6f8;
    font-size: 1.18rem;
    font-weight: 760;
    letter-spacing: .08em;
}
.brand-sub {
    color: #536372;
    font-size: .82rem;
    letter-spacing: .14em;
    text-transform: uppercase;
    margin-top: 3px;
}
.nav-label {
    color: #4e5e6c;
    font-size: .70rem;
    font-weight: 700;
    letter-spacing: .14em;
    text-transform: uppercase;
    margin: 20px 8px 7px;
}
.sidebar-status {
    border-top: 1px solid var(--line-soft);
    margin-top: 18px;
    padding: 14px 7px 0;
    color: #667582;
    font-size: .76rem;
    line-height: 1.9;
}
.sidebar-status strong { color: #b8c4ce; font-weight: 650; }

/* Sidebar navigation: full-width, compact, scrollbar hidden */
[data-testid="stSidebar"] > div:first-child { scrollbar-width:none !important; }
[data-testid="stSidebar"] > div:first-child::-webkit-scrollbar { width:0 !important; display:none !important; }
[data-testid="stSidebar"] div[role="radiogroup"] { width:100% !important; gap:5px !important; }
[data-testid="stSidebar"] div[role="radiogroup"] label {
    width:100% !important; min-height:38px !important; box-sizing:border-box !important;
    margin:0 !important; padding:8px 10px !important; border:1px solid transparent !important;
    border-radius:4px !important; display:flex !important; align-items:center !important;
}
[data-testid="stSidebar"] div[role="radiogroup"] label:hover { background:#0d171e !important; border-color:#1d303a !important; }
[data-testid="stSidebar"] div[role="radiogroup"] label[data-checked="true"] { background:#101d24 !important; border-color:#294651 !important; }

/* Global shell */
.topbar {
    height: 44px;
    border-bottom: 1px solid var(--line-soft);
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin: 0 -1rem 12px;
    padding: 0 20px;
    background: rgba(10,15,20,.94);
}
.topbar-left { display: flex; align-items: center; gap: 0; }
.topbar-brand { color:#90a5ad; font-size:.72rem; font-weight:760; letter-spacing:.12em; }
.topbar-title { color: #dce5eb; font-size: .88rem; font-weight: 650; letter-spacing: .06em; }
.system-state { color: #6fc19d; font-size: .76rem; font-weight: 700; letter-spacing: .09em; }
.state-dot { display:inline-block; width:6px; height:6px; border-radius:50%; background:#64b990; margin-right:7px; }

.page-kicker {
    display:none;
    color: var(--accent);
    font-size: .82rem;
    font-weight: 750;
    letter-spacing: .15em;
    text-transform: uppercase;
    margin-bottom: 5px;
}
.page-title {
    color: #edf2f6;
    font-size: 1.78rem;
    line-height: 1.15;
    font-weight: 720;
    margin: 0 0 10px;
}
.page-title {
    animation: socFadeUp .42s ease both;
}
.page-description { animation: socFadeUp .42s .04s ease both; }
.page-description { color: var(--muted); font-size: .86rem; margin: 5px 0 13px; }

.section-title {
    color: #cbd5de;
    font-size: .82rem;
    font-weight: 720;
    letter-spacing: .08em;
    text-transform: uppercase;
    margin: 13px 0 7px;
}

.panel {
    background: var(--surface);
    border: 1px solid var(--line);
    border-radius: 5px;
    padding: 15px;
}
.panel-tight { padding: 11px 13px; }
.panel-title { color:#d8e1e8; font-size:.75rem; font-weight:700; }
.panel-meta { color:#687887; font-size:.65rem; }

/* AI analysis typography: keep generated Markdown compact inside the SOC workspace. */
.stMarkdown h1 { font-size: 1.12rem !important; line-height: 1.25 !important; margin: .25rem 0 .65rem !important; }
.stMarkdown h2 { font-size: .92rem !important; line-height: 1.3 !important; margin: .8rem 0 .35rem !important; }
.stMarkdown h3 { font-size: .82rem !important; line-height: 1.3 !important; margin: .65rem 0 .3rem !important; }
.stMarkdown p, .stMarkdown li { font-size: .82rem; line-height: 1.55; }

/* Severity treatment: color is reserved for analyst-priority signals. */
.severity-banner {
    display:flex;
    align-items:center;
    gap:10px;
    padding:10px 12px;
    margin-bottom:12px;
    border:1px solid var(--line);
    border-left:4px solid;
    border-radius:4px;
    background:#0d141b;
}
.severity-dot {
    width:9px;
    height:9px;
    border-radius:50%;
    flex:0 0 9px;
}
.severity-critical { border-left-color:#ff4d5a; }
.severity-critical .severity-dot { background:#ff4d5a; }
.severity-high { border-left-color:#ff9f43; }
.severity-high .severity-dot { background:#ff9f43; }
.severity-medium { border-left-color:#f4c95d; }
.severity-medium .severity-dot { background:#f4c95d; }
.severity-low { border-left-color:#45c98a; }
.severity-low .severity-dot { background:#45c98a; }

.severity-word-critical { color:#ff6670; }
.severity-word-high { color:#ffad5c; }
.severity-word-medium { color:#f4cf6d; }
.severity-word-low { color:#55d39a; }

.nav-group-label {
    color:#5f7180;
    font-size:.61rem;
    font-weight:800;
    letter-spacing:.12em;
    margin:18px 0 6px;
}

.overview-metric, .investigation-metric {
    display:flex;
    justify-content:space-between;
    align-items:center;
    width:100%;
    box-sizing:border-box;
    background:var(--surface);
    border:1px solid var(--line);
    border-radius:5px;
    padding:14px 17px;
    margin-bottom:8px;
}
.overview-metric-value, .investigation-metric-value {
    font-size:1.25rem;
    line-height:1;
    font-weight:800;
    color:#e6edf2;
    text-align:right;
}
.investigation-metric-value {
    font-size:1.1rem;
}
.metric-note {
    color:#687887;
    font-size:.72rem;
    margin-top:3px;
}
.workflow-vertical {
    display:flex;
    flex-direction:column;
    gap:0;
}
.workflow-vertical .workflow-item {
    width:100%;
    box-sizing:border-box;
    min-height:44px;
}

/* Metric strip */
.metric-strip {
    display:flex;
    flex-direction:column;
    border:1px solid var(--line);
    background:var(--surface);
    border-radius:5px;
    overflow:hidden;
}
.metric-cell { margin-bottom:10px; padding:12px 14px; border-bottom:1px solid var(--line); }
.metric-cell:last-child { border-bottom:0; }
.metric-label { color:#697987; font-size:.70rem; text-transform:uppercase; letter-spacing:.07em; }
.metric-value { color:#edf2f5; font-size:1.35rem; font-weight:720; margin-top:4px; }
.metric-note { color:#596875; font-size:.70rem; margin-top:2px; }

/* Alert rows */
.alert-row {
    display:grid;
    grid-template-columns: 88px 1fr 120px 100px 96px;
    gap:10px;
    align-items:center;
    padding:11px 12px;
    border-bottom:1px solid var(--line-soft);
    font-size:.71rem;
}
.alert-row:last-child { border-bottom:0; }
.alert-row:hover { background:#111a23; }
.alert-head { color:#5e6d79; font-size:.6rem; text-transform:uppercase; letter-spacing:.06em; }
.alert-main { color:#d9e2e9; font-weight:620; }
.alert-sub { color:#667582; font-size:.63rem; margin-top:3px; }
.sev { font-size:.70rem; font-weight:800; letter-spacing:.05em; }
.sev-critical { color:var(--critical); }
.sev-high { color:var(--high); }
.sev-medium { color:var(--medium); }
.sev-low { color:var(--low); }
.status-open { color:#e59a58; }
.status-investigating { color:#63c1cc; }
.status-contained { color:#d0b25b; }
.status-resolved, .status-closed { color:#69b995; }

/* Workflow */
.workflow { display:flex; flex-direction:column; border:1px solid var(--line); border-radius:5px; overflow:hidden; }
.workflow-item { width:100%; box-sizing:border-box; padding:10px 12px; background:var(--surface); color:#596976; text-align:left; font-size:.70rem; font-weight:720; letter-spacing:.08em; border-bottom:1px solid var(--line); }
.workflow-item:last-child { border-bottom:0; }
.workflow-item.active { color:#79cad3; background:#10242a; }
.workflow-num { display:block; font-size:.64rem; color:#465662; margin-bottom:2px; }
.workflow-item.active .workflow-num { color:#4b9da7; }

/* Evidence / IOC */
.ioc {
    display:inline-block;
    border:1px solid #273744;
    background:#0c141c;
    color:#aab9c4;
    border-radius:3px;
    padding:4px 7px;
    margin:0 5px 5px 0;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size:.64rem;
}
.detail-label { color:#596976; font-size:.59rem; text-transform:uppercase; letter-spacing:.08em; }
.detail-value { color:#d4dee5; font-size:.73rem; margin-top:2px; word-break:break-word; }
.investigation-evidence-row {
    display:flex;
    flex-direction:column;
    border-top:1px solid var(--line);
    border-bottom:1px solid var(--line);
    background:var(--surface-3);
}
.investigation-evidence-item {
    min-width:0;
    padding:10px 12px;
    border-bottom:1px solid var(--line-soft);
}
.investigation-evidence-item:last-child { border-bottom:0; }
.investigation-evidence-item .detail-value { display:block; }
.ioc-row { padding:0 0 2px; }

/* Inputs and buttons */
.stTextInput input, .stTextArea textarea,
[data-baseweb="select"] > div {
    background:#0b1219 !important;
    border-color:#263542 !important;
    color:#e4ebf0 !important;
    border-radius:4px !important;
}
.stTextInput input:focus, .stTextArea textarea:focus { border-color:#3d727a !important; box-shadow:0 0 0 1px #244c53 !important; }
.stButton > button {
    border-radius:4px;
    border:1px solid #2a3b48;
    background:#121c25;
    color:#d8e2e8;
    font-size:.82rem;
    font-weight:680;
    min-height:34px;
}
.stButton > button:hover { background:#16242d; border-color:#3b626b; color:#fff; }
.stButton > button[kind="primary"] { background:#16414a; border-color:#28616b; }
.stButton > button[kind="primary"]:hover { background:#1b4d57; }

[data-testid="stMetric"] {
    background:#0f171f;
    border:1px solid var(--line);
    border-radius:4px;
    padding:10px 12px !important;
}
[data-testid="stMetricLabel"] { color:#6b7b88 !important; font-size:.70rem !important; text-transform:uppercase; letter-spacing:.06em; }
[data-testid="stMetricValue"] { color:#e9eef2 !important; font-size:1.22rem !important; }

[data-testid="stDataFrame"] { border:1px solid var(--line); border-radius:4px; overflow:hidden; }
[data-testid="stDataFrame"] * { font-size:.82rem; }

div[data-testid="stExpander"] { background:var(--surface); border:1px solid var(--line); border-radius:4px; margin-top:10px; }
div[data-testid="stDownloadButton"] { margin-top:10px; }
.stProgress > div > div { background:#2c7780; }

.empty-state {
    border:1px dashed #263541;
    background:#0c131a;
    border-radius:5px;
    padding:34px 22px;
    text-align:center;
}
.empty-title { color:#b8c5ce; font-size:.8rem; font-weight:650; }
.empty-copy { color:#5e6d79; font-size:.68rem; margin-top:5px; }

@media (max-width: 900px) {
    .alert-row { grid-template-columns:75px 1fr 90px; }
    .alert-row > :nth-child(4), .alert-row > :nth-child(5) { display:none; }
    .topbar { padding:0 14px; }
    .topbar-context, .system-state { display:none; }
}

@media (max-width: 600px) {
    .metric-strip { grid-template-columns:1fr; }
    .metric-cell { margin-bottom:10px; border-right:0 !important; border-bottom:1px solid var(--line) !important; }
    .metric-cell:last-child { border-bottom:0 !important; }
    .investigation-evidence-row { grid-template-columns:1fr; }
    .investigation-evidence-item { border-right:0 !important; border-bottom:1px solid var(--line-soft); }
    .investigation-evidence-item:last-child { border-bottom:0; }
    .report-entry { border:1px solid #1d2a35; padding:18px; margin-bottom:18px; background:#0d141b; }
    .report-entry-header { display:flex; justify-content:space-between; align-items:flex-start; gap:16px; margin-bottom:16px; }
    .report-entry-title { font-size:1rem; font-weight:700; color:#dce6ee; }
    .report-entry-meta { margin-top:5px; color:#6f7f8d; font-size:.72rem; }
    .page-title { font-size:1.45rem; }
    .page-description { font-size:.82rem; }
    .overview-metric, .investigation-metric { padding:12px 13px; }
    .workflow-item { font-size:.64rem; }
}

/* Incident report presentation */
.report-entry-title { font-size:1rem !important; line-height:1.25 !important; font-weight:700 !important; color:#dce6ee !important; }
.report-entry-meta { margin-top:5px !important; color:#6f7f8d !important; font-size:.72rem !important; line-height:1.45 !important; }
.report-action-row { width:100%; margin-top:4px; }
[class*="st-key-reportactions_"] [data-testid="stDownloadButton"] > button,
[class*="st-key-reportactions_"] [data-testid="stButton"] > button {
    width:100% !important;
    min-height:44px !important;
    height:44px !important;
    box-sizing:border-box !important;
    border-radius:4px !important;
    font-size:.82rem !important;
    font-weight:700 !important;
    letter-spacing:.01em !important;
    transition:transform .22s ease, border-color .22s ease, background .22s ease, box-shadow .22s ease, color .22s ease !important;
}
[class*="st-key-reportactions_"] [data-testid="stDownloadButton"] > button {
    background:#121c25 !important;
    border:1px solid #2a3b48 !important;
    color:#d8e2e8 !important;
}
[class*="st-key-reportactions_"] [data-testid="stDownloadButton"] > button:hover {
    transform:translateY(-2px) !important;
    background:#162d36 !important;
    border-color:#56b8c3 !important;
    color:#f2feff !important;
    box-shadow:0 0 16px rgba(75,183,196,.25), 0 6px 20px rgba(0,0,0,.20) !important;
}
[class*="st-key-reportactions_"] [data-testid="stButton"] > button {
    background:#111a23 !important;
    border:1px solid #31414d !important;
    color:#b9c5cd !important;
}
[class*="st-key-reportactions_"] [data-testid="stButton"] > button:hover {
    transform:translateY(-2px) !important;
    background:#24161a !important;
    border-color:#b65b66 !important;
    color:#ffc2c8 !important;
    box-shadow:0 0 16px rgba(196,76,91,.22), 0 6px 20px rgba(0,0,0,.20) !important;
}
[class*="st-key-reportactions_"] .stDownloadButton,
[class*="st-key-reportactions_"] .stButton {
    width:100% !important;
}
[class*="st-key-reportactions_"] > div {
    width:100% !important;
}
[class*="st-key-reportactions_"] [data-testid="stHorizontalBlock"] {
    display:flex !important;
    align-items:stretch !important;
    gap:10px !important;
    width:100% !important;
}
[class*="st-key-reportactions_"] [data-testid="stColumn"] {
    flex:1 1 0 !important;
    width:calc(50% - 5px) !important;
    min-width:0 !important;
    display:flex !important;
    align-items:stretch !important;
}
[class*="st-key-reportactions_"] [data-testid="stColumn"] > div {
    width:100% !important;
}
[class*="st-key-reportactions_"] .stDownloadButton,
[class*="st-key-reportactions_"] .stButton {
    width:100% !important;
    margin:0 !important;
}

/* Status confirmation */
.status-toast {
    display:flex;
    align-items:center;
    gap:9px;
    width:fit-content;
    max-width:100%;
    margin:0 0 18px 0;
    padding:10px 15px;
    border:1px solid #28594c;
    border-radius:5px;
    background:rgba(10,31,26,.96);
    color:#82d6ae;
    font-size:.73rem;
    font-weight:700;
    letter-spacing:.025em;
    box-shadow:0 0 20px rgba(72,190,143,.10);
    animation:statusToastIn .3s ease both;
}
.status-toast-inline {
    margin-top: 12px;
    margin-bottom: 14px;
    margin-left: 0;
}

.status-toast-dot {
    width:6px;
    height:6px;
    flex:0 0 6px;
    border-radius:50%;
    background:#65c99e;
    box-shadow:0 0 8px rgba(101,201,158,.9);
}
@keyframes statusToastIn {
    from { opacity:0; transform:translateY(-6px); }
    to { opacity:1; transform:translateY(0); }
}

</style>
""",
    unsafe_allow_html=True,
)


# -----------------------------------------------------------------------------
# STATE / DATA HELPERS
# -----------------------------------------------------------------------------
@st.cache_resource
def get_runtime_workspace():
    return {
        "scan_history": pd.DataFrame(
            columns=["Timestamp", "Target Type", "Input Preview", "Risk Score / Confidence", "Verdict"]
        ),
        "email_result": None,
        "website_result": None,
        "latest_incident_report": None,
        "incident_reports": [],
    }


runtime_workspace = get_runtime_workspace()

# Keep the latest generated report in Streamlit session state as well as the
# runtime workspace. This preserves the original Reports workflow across
# page navigation/reruns without changing the detection pipeline.
if "latest_incident_report" not in st.session_state:
    st.session_state["latest_incident_report"] = runtime_workspace.get("latest_incident_report")


@st.cache_resource
def load_ml_pipeline():
    try:
        model = joblib.load("models/phishing_model.pkl")
        vectorizer = joblib.load("models/tfidf_vectorizer.pkl")
        return model, vectorizer
    except Exception:
        return None, None


email_model, vectorizer = load_ml_pipeline()


def clean_text(text):
    text = str(text).lower()
    text = re.sub(r"http\S+", "", text)
    text = re.sub(r"[^a-zA-Z\s]", "", text)
    return re.sub(r"\s+", " ", text).strip()


def analyze_url(url):
    score = 0
    reasons = []
    if not url:
        return score, reasons
    if len(url) > 75:
        score += 20
        reasons.append("LONG_URL")
    if url.count(".") > 3:
        score += 15
        reasons.append("EXCESS_SUBDOMAINS")
    if url.count("-") >= 2:
        score += 15
        reasons.append("MULTIPLE_HYPHENS")
    elif "-" in url:
        score += 8
        reasons.append("HYPHENATED_DOMAIN")
    if not url.lower().startswith("https://"):
        score += 20
        reasons.append("MISSING_HTTPS")
    parsed = urlparse(url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url) else "http://" + url)
    host = (parsed.hostname or "").lower()
    if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", host):
        score += 25
        reasons.append("IP_ADDRESS_HOST")
    if "@" in url:
        score += 20
        reasons.append("AT_SYMBOL_OBFUSCATION")
    if parsed.port is not None and parsed.port not in (80, 443):
        score += 15
        reasons.append("NONSTANDARD_PORT")
    if "xn--" in host:
        score += 20
        reasons.append("PUNYCODE_DOMAIN")
    suspicious_words = [
        "login", "verify", "verification", "secure", "security",
        "update", "account", "bank", "paypal", "signin", "confirm",
    ]
    for word in suspicious_words:
        if word in url.lower():
            score += 10
            reasons.append(f"KEYWORD_{word.upper()}")
    return min(score, 100), reasons


def add_history_record(target_type, target_input, score, verdict):
    preview = target_input[:50] + "..." if len(target_input) > 50 else target_input
    row = pd.DataFrame([{
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Target Type": target_type,
        "Input Preview": preview,
        "Risk Score / Confidence": score,
        "Verdict": verdict,
    }])
    runtime_workspace["scan_history"] = pd.concat(
        [runtime_workspace["scan_history"], row], ignore_index=True
    )


def add_security_alert(source, threat_type, confidence, risk_score, indicators, summary):
    alert = create_alert(
        source=source,
        threat_type=threat_type,
        confidence=confidence,
        risk_score=risk_score,
        indicators=indicators,
        summary=summary,
    )
    save_alert(alert)
    return alert


def set_latest_report(report):
    """Keep the latest report available to the Reports page without changing report generation."""
    runtime_workspace["latest_incident_report"] = report
    st.session_state["latest_incident_report"] = report


def severity_class(severity):
    return {
        "CRITICAL": "sev-critical",
        "HIGH": "sev-high",
        "MEDIUM": "sev-medium",
        "LOW": "sev-low",
    }.get(str(severity).upper(), "")


def status_class(status):
    return "status-" + str(status).lower().replace(" ", "-")


def render_page_header(kicker, title, description=""):
    # Keep a single clear page title. The old kicker/section combination created
    # duplicated labels and unnecessary vertical spacing.
    st.markdown(f'<h1 class="page-title">{title}</h1>', unsafe_allow_html=True)
    if description:
        st.markdown(f'<div class="page-description">{description}</div>', unsafe_allow_html=True)


def render_metric_strip(items):
    html = '<div class="metric-strip">'
    for label, value, note in items:
        html += (
            '<div class="metric-cell">'
            f'<div class="metric-label">{label}</div>'
            f'<div class="metric-value">{value}</div>'
            f'<div class="metric-note">{note}</div>'
            '</div>'
        )
    html += '</div>'
    st.markdown(html, unsafe_allow_html=True)


def render_alert_table(alerts, limit=None):
    rows = alerts[:limit] if limit else alerts
    if not rows:
        st.markdown(
            '<div class="empty-state"><div class="empty-title">No security alerts</div>'
            '<div class="empty-copy">Run an email or domain analysis to create an alert.</div></div>',
            unsafe_allow_html=True,
        )
        return
    header = (
        '<div class="panel">'
        '<div class="alert-row alert-head">'
        '<div>Severity</div><div>Alert</div><div>Source</div><div>Status</div><div>Time</div>'
        '</div>'
    )
    body = ""
    for a in rows:
        sev = str(a.get("severity", "LOW")).upper()
        status = str(a.get("status", "OPEN")).upper()
        body += (
            '<div class="alert-row">'
            f'<div class="sev {severity_class(sev)}">{sev}</div>'
            f'<div><div class="alert-main">{a.get("threat_type", "Security Alert")}</div>'
            f'<div class="alert-sub">{a.get("alert_id", "—")} · {a.get("summary", "")}</div></div>'
            f'<div class="alert-sub">{a.get("source", "—")}</div>'
            f'<div class="sev {status_class(status)}">{status}</div>'
            f'<div class="alert-sub">{str(a.get("timestamp", "—"))[-8:]}</div>'
            '</div>'
        )
    st.markdown(header + body + '</div>', unsafe_allow_html=True)


def render_iocs(indicators):
    if not indicators:
        st.caption("No indicators recorded for this alert.")
        return
    st.markdown(
        "".join(f'<span class="ioc">{str(x)}</span>' for x in indicators),
        unsafe_allow_html=True,
    )


def extract_email_metadata(email_text):
    """Extract lightweight metadata from a pasted raw email without requiring extra fields."""
    sender = "Not provided"
    subject = "Not provided"

    sender_match = re.search(r"(?im)^\\s*(?:from|sender)\\s*:\\s*(.+?)\\s*$", email_text)
    subject_match = re.search(r"(?im)^\\s*subject\\s*:\\s*(.+?)\\s*$", email_text)

    if sender_match:
        sender = sender_match.group(1).strip()
    if subject_match:
        subject = subject_match.group(1).strip()

    links = "Yes" if extract_iocs(email_text).get("urls") else "No"
    attachments = "Mentioned" if re.search(
        r"(?i)\\b(attachment|attached|enclosed|filename|\\.pdf\\b|\\.docx\\b|\\.xlsx\\b|\\.zip\\b)",
        email_text,
    ) else "Not indicated"

    return sender, subject, links, attachments


def delete_incident_report_local(report_id):
    """Delete one incident report without deleting its underlying SOC alert."""
    db_path = Path(__file__).resolve().parent / "data" / "soc_alerts.db"
    conn = sqlite3.connect(str(db_path), timeout=10)
    try:
        cursor = conn.execute(
            "DELETE FROM incident_reports WHERE report_id = ?",
            (int(report_id),),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------
# APPLICATION SHELL
# -----------------------------------------------------------------------------
# The landing screen is deliberately separate from the SOC workspace.  The
# navigation widget is only created after the user enters the workspace, which
# avoids Streamlit's widget/session-state mutation error.
if "show_landing" not in st.session_state:
    st.session_state["show_landing"] = True


def enter_workspace():
    st.session_state["show_landing"] = False


def return_to_landing():
    st.session_state["show_landing"] = True

try:
    current_alerts = get_all_alerts()
    db_state = "ONLINE"
except Exception:
    current_alerts = []
    db_state = "UNAVAILABLE"

if st.session_state["show_landing"]:
    landing_alerts = len(current_alerts)
    landing_status = "OPERATIONAL" if db_state == "ONLINE" and email_model is not None else "DEGRADED"

    st.markdown(
        f"""
        <style>
        html, body, [data-testid="stAppViewContainer"] {{ overflow:hidden !important; }}
        .landing-page {{
            position:fixed !important;
            top:0 !important;
            right:0 !important;
            bottom:0 !important;
            left:0 !important;
            width:100% !important;
            height:100% !important;
            min-height:100vh;
            margin:0 !important;
            border:0 !important;
            background:
                radial-gradient(circle at 78% 35%, rgba(61,170,185,.15), transparent 24%),
                radial-gradient(circle at 16% 74%, rgba(33,103,119,.11), transparent 30%),
                #060b10;
            padding:clamp(44px,8vh,86px) clamp(40px,8vw,130px) 120px;
            box-sizing:border-box;
            overflow:hidden;
        }}
        .landing-grid {{ position:absolute; inset:-8%; pointer-events:none; opacity:.7;
            background-image:linear-gradient(rgba(90,132,145,.045) 1px,transparent 1px),linear-gradient(90deg,rgba(90,132,145,.045) 1px,transparent 1px);
            background-size:48px 48px; animation:gridDrift 18s linear infinite;
            mask-image:linear-gradient(to bottom,black 10%,transparent 95%); }}
        @keyframes gridDrift {{ to {{ transform:translate3d(48px,48px,0); }} }}
        .binary-wave-field {{ position:absolute; inset:-15% -10% -15% 35%; overflow:hidden; pointer-events:none; opacity:.72; transform:rotate(-6deg);
            mask-image:linear-gradient(90deg,transparent,black 10%,black 86%,transparent); }}
        .binary-wave {{ position:absolute; left:-12%; width:125%; white-space:nowrap; color:#66d8e4; font:650 12px/2 ui-monospace,SFMono-Regular,Menlo,monospace; letter-spacing:.25em; text-shadow:0 0 14px rgba(74,184,196,.4); will-change:transform; }}
        .binary-wave:nth-child(1) {{ top:8%; opacity:.22; animation:waveA 16s ease-in-out infinite alternate; }}
        .binary-wave:nth-child(2) {{ top:25%; opacity:.14; animation:waveB 21s ease-in-out infinite alternate; }}
        .binary-wave:nth-child(3) {{ top:43%; opacity:.18; animation:waveC 18s ease-in-out infinite alternate; }}
        .binary-wave:nth-child(4) {{ top:61%; opacity:.11; animation:waveB 24s ease-in-out infinite alternate-reverse; }}
        .binary-wave:nth-child(5) {{ top:78%; opacity:.14; animation:waveA 22s ease-in-out infinite alternate-reverse; }}
        @keyframes waveA {{ from {{ transform:translate3d(-5%,0,0) skewX(-9deg); }} to {{ transform:translate3d(7%,24px,0) skewX(9deg); }} }}
        @keyframes waveB {{ from {{ transform:translate3d(8%,12px,0) skewX(8deg); }} to {{ transform:translate3d(-7%,-22px,0) skewX(-10deg); }} }}
        @keyframes waveC {{ from {{ transform:translate3d(-8%,-12px,0) skewX(-11deg); }} to {{ transform:translate3d(6%,27px,0) skewX(11deg); }} }}
        .landing-orbit {{ position:absolute; z-index:1; right:8%; top:18%; width:min(40vw,520px); aspect-ratio:1; border:1px solid rgba(75,170,183,.13); border-radius:50%; transform:rotate(-18deg); animation:orbitFloat 10s ease-in-out infinite; }}
        .landing-orbit::before,.landing-orbit::after {{ content:""; position:absolute; inset:12%; border:1px solid rgba(75,170,183,.10); border-radius:50%; }}
        .landing-orbit::after {{ inset:29%; border-style:dashed; animation:orbitSpin 24s linear infinite; }}
        @keyframes orbitFloat {{ 0%,100% {{ transform:rotate(-18deg) translateY(0); }} 50% {{ transform:rotate(-14deg) translateY(-10px); }} }}
        @keyframes orbitSpin {{ to {{ transform:rotate(360deg); }} }}
        .landing-node {{ position:absolute; z-index:2; width:6px; height:6px; border-radius:50%; background:#61c3cd; box-shadow:0 0 18px rgba(97,195,205,.8); animation:nodePulse 2.8s ease-in-out infinite; }}
        .landing-node.n1 {{ right:30%; top:27%; }} .landing-node.n2 {{ right:17%; top:54%; animation-delay:.8s; }} .landing-node.n3 {{ right:37%; top:67%; animation-delay:1.4s; }}
        @keyframes nodePulse {{ 0%,100% {{ opacity:.25; transform:scale(.75); }} 50% {{ opacity:1; transform:scale(1.25); }} }}
        .landing-scan {{ position:absolute; z-index:2; left:0; right:0; top:-10%; height:1px; background:linear-gradient(90deg,transparent,rgba(92,203,214,.55),transparent); box-shadow:0 0 18px rgba(92,203,214,.25); animation:scanDown 7s ease-in-out infinite; pointer-events:none; }}
        @keyframes scanDown {{ 0% {{ transform:translateY(0); opacity:0; }} 12% {{ opacity:1; }} 85% {{ opacity:.55; }} 100% {{ transform:translateY(120vh); opacity:0; }} }}
        .landing-vignette {{ position:absolute; z-index:0; inset:0; pointer-events:none; background:linear-gradient(90deg,rgba(6,11,16,.99) 0%,rgba(6,11,16,.90) 30%,rgba(6,11,16,.30) 68%,rgba(6,11,16,.62) 100%); }}
        .landing-content {{
            position:relative;
            z-index:3;
            width:min(1320px, 90vw);
            max-width:1320px;
            height:100%;
            margin:0 auto;
            display:flex;
            flex-direction:column;
            justify-content:center;
            padding:0;
            transform:translateY(-2vh);
        }}
        .landing-kicker {{ display:flex; align-items:center; gap:10px; color:#70a9b1; font-size:.88rem; font-weight:800; letter-spacing:.19em; margin-bottom:17px; animation:socFadeUp .6s ease both; }}
        .landing-kicker-dot {{ width:6px; height:6px; border-radius:50%; background:#57bcc6; box-shadow:0 0 16px rgba(87,188,198,.7); animation:socGlow 2s ease-in-out infinite; }}
        .landing-brandline {{ display:flex; align-items:center; gap:11px; color:#a5bac3; font-size:1.02rem; font-weight:750; letter-spacing:.13em; margin-bottom:23px; animation:socFadeUp .6s .05s ease both; }}
        .landing-mark {{ width:32px; height:32px; display:inline-flex; align-items:center; justify-content:center; border:1px solid #31505a; background:#0b171e; color:#72cbd4; font:700 .68rem ui-monospace,monospace; clip-path:polygon(50% 0,94% 24%,84% 78%,50% 100%,16% 78%,6% 24%); box-shadow:inset 0 0 18px rgba(56,153,168,.08); }}
        .landing-title {{ color:#eef5f7; font-size:clamp(5.6rem,10.2vw,10.5rem); line-height:.86; font-weight:850; letter-spacing:-.065em; margin:0; animation:socFadeUp .7s .1s ease both; }}
        .landing-title span {{ color:#68c0ca; text-shadow:0 0 28px rgba(74,184,196,.12); }}
        .landing-title-sub {{ margin-top:24px; color:#a1b6be; font-size:1.36rem; letter-spacing:.055em; animation:socFadeUp .7s .16s ease both; }}
        .landing-copy {{ max-width:860px; margin:20px 0 0; color:#81959e; font-size:1.18rem; line-height:1.72; animation:socFadeUp .7s .22s ease both; }}
        .landing-terminal {{ margin-top:24px; color:#57a5ae; font:600 .76rem ui-monospace,monospace; letter-spacing:.12em; animation:socFadeUp .7s .28s ease both; }}
        .landing-terminal::after {{ content:"_"; animation:cursorBlink 1s steps(1) infinite; }}
        @keyframes cursorBlink {{ 50% {{ opacity:0; }} }}
                /* Streamlit renders st.button outside the markdown wrapper.
                   Target the landing-only button directly so it is truly centered. */
        body:has(.landing-page) [data-testid="stButton"] {{
            position:fixed !important;
            z-index:999 !important;
            left:50% !important;
            bottom:7vh !important;
            width:min(420px,88vw) !important;
            margin:0 !important;
            transform:translateX(-50%) !important;
            display:flex !important;
            justify-content:center !important;
            animation:socFadeUp .7s .34s ease both;
        }}
        body:has(.landing-page) [data-testid="stButton"] > button {{
            width:min(390px,88vw) !important;
            min-height:58px !important;
            border:1px solid #3f9eaa !important;
            border-radius:6px !important;
            background:linear-gradient(135deg,#0b252d 0%,#15515b 46%,#0b252d 100%) !important;
            color:#e6fdff !important;
            font-size:.9rem !important;
            font-weight:850 !important;
            letter-spacing:.15em !important;
            box-shadow:0 0 18px rgba(66,197,209,.18), inset 0 0 24px rgba(66,197,209,.08);
            position:relative;
            overflow:hidden;
            transition:transform .28s ease, border-color .28s ease, box-shadow .28s ease, background .28s ease;
        }}
        body:has(.landing-page) [data-testid="stButton"] > button::before {{
            content:"";
            position:absolute;
            top:0; bottom:0;
            left:-40%;
            width:32%;
            transform:skewX(-18deg);
            background:linear-gradient(90deg,transparent,rgba(173,251,255,.26),transparent);
            animation:buttonSweep 3.2s ease-in-out infinite;
        }}
        @keyframes buttonSweep {{
            0%,55% {{ left:-45%; opacity:0; }}
            65% {{ opacity:1; }}
            100% {{ left:125%; opacity:0; }}
        }}
        body:has(.landing-page) [data-testid="stButton"] > button:hover {{
            transform:translateY(-5px) scale(1.035);
            border-color:#86f5fc !important;
            background:linear-gradient(135deg,#123f49 0%,#1c6a75 48%,#123f49 100%) !important;
            box-shadow:0 0 12px rgba(102,228,238,.72), 0 0 32px rgba(102,228,238,.34), 0 0 68px rgba(102,228,238,.14), inset 0 0 30px rgba(130,242,250,.12);
        }}
        body:has(.landing-page) [data-testid="stButton"] > button:active {{
            transform:translateY(-2px) scale(1.01);
        }}
        @media(max-width:850px) {{ .landing-page {{ padding:38px 24px; }} .landing-orbit {{ opacity:.45; right:-18%; width:65vw; }} }}
        @media(max-width:560px) {{
            .landing-page {{ padding:30px 18px 110px; }}
            .landing-content {{ width:min(92vw, 760px); }}
            .landing-title {{ font-size:3.6rem; }}
            .landing-title-sub {{ font-size:.9rem; }}
            .landing-copy {{ font-size:.86rem; }}
            .binary-wave-field {{ left:0; opacity:.45; }}
            .landing-orbit {{ display:none; }}
            body:has(.landing-page) [data-testid="stButton"] {{ bottom:5vh !important; width:min(390px,88vw) !important; }}
        }}
        </style>
        <div class="landing-page">
            <div class="landing-grid"></div>
            <div class="binary-wave-field">
                <div class="binary-wave">0101 1010 0011 1100 0101 0110 1001 1110 0010</div>
                <div class="binary-wave">1010 0101 1101 0011 0110 1011 0100 1110 1001</div>
                <div class="binary-wave">0011 1011 0101 1100 1001 0110 1110 0010 1011</div>
                <div class="binary-wave">1100 0101 0011 1010 0111 1101 0010 1011 0100</div>
                <div class="binary-wave">0110 1001 1110 0011 1010 0101 1100 0111 1001</div>
            </div>
            <div class="landing-orbit"></div>
            <span class="landing-node n1"></span><span class="landing-node n2"></span><span class="landing-node n3"></span>
            <div class="landing-scan"></div>
            <div class="landing-vignette"></div>
            <div class="landing-content">
                <div class="landing-kicker"><span class="landing-kicker-dot"></span> SECURITY OPERATIONS PLATFORM · {landing_status}</div>
                <div class="landing-brandline"><span class="landing-mark">01</span><span>AI CYBERSHIELD / SOC</span></div>
                <h1 class="landing-title">DEFEND THE<br><span>DIGITAL FRONTIER.</span></h1>
                <div class="landing-title-sub">AI-assisted threat detection · Investigation · Response</div>
                <p class="landing-copy">A focused security operations environment for identifying phishing, analyzing suspicious web activity, investigating incidents and preserving analyst decisions as structured security intelligence.</p>
                <div class="landing-terminal">INITIALIZING SECURITY OPERATIONS WORKSPACE...</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown('<div class="landing-enter-wrap">', unsafe_allow_html=True)
    st.button("ENTER SOC WORKSPACE  →", type="primary", on_click=enter_workspace, key="enter_soc_workspace")
    st.markdown('</div>', unsafe_allow_html=True)
    st.stop()

with st.sidebar:
    st.markdown(
        '<div class="brand"><span>AI CYBERSHIELD</span></div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="brand-sub">Security Operations Console</div>'
        '<div class="brand-sub" style="margin-top:4px;color:#657887;letter-spacing:.05em;text-transform:none;">Detect · Triage · Investigate · Resolve</div>',
        unsafe_allow_html=True,
    )

    st.markdown('<div class="nav-label">Workspace</div>', unsafe_allow_html=True)
    app_mode = st.radio(
        "Workspace",
        [
            "SOC Overview",
            "Alert Queue",
            "Incident Investigation",
            "Email Security",
            "Domain Security",
            "Incident Reporting",
        ],
        label_visibility="collapsed",
        key="Workspace",
    )

    st.markdown('<div class="nav-label">Environment</div>', unsafe_allow_html=True)
    global_query = st.text_input(
        "Global search",
        placeholder="Alert ID, domain, IOC...",
        label_visibility="collapsed",
        key="global_search",
    )

    st.markdown(
        f'<div class="sidebar-status">'
        f'<div>DATABASE <strong>{db_state}</strong></div>'
        f'<div>ENGINE <strong>{"READY" if email_model is not None else "UNAVAILABLE"}</strong></div>'
        f'<div>ALERTS <strong>{len(current_alerts)}</strong></div>'
        f'<div>SESSION SCANS <strong>{len(runtime_workspace["scan_history"])}</strong></div>'
        '</div>',
        unsafe_allow_html=True,
    )

page_context = {
    "SOC Overview": "SOC Overview",
    "Alert Queue": "Alert Queue",
    "Incident Investigation": "Incident Investigation",
    "Email Security": "Email Security",
    "Domain Security": "Domain Security",
    "Incident Reporting": "Incident Reporting",
}
context_title = page_context.get(app_mode, app_mode)

st.markdown(
    f'<div class="topbar">'
    f'<div class="topbar-left"><span class="topbar-brand">AI CYBERSHIELD / SOC</span></div>'
    f'<div class="system-state"><span class="state-dot"></span>{db_state} · ENGINE {"READY" if email_model is not None else "UNAVAILABLE"}</div>'
    f'</div>',
    unsafe_allow_html=True,
)

if st.session_state.pop("flash_success", None):
    status_message = st.session_state.pop(
        "flash_success_text",
        "STATUS UPDATED · The incident status has been updated successfully.",
    )
    st.markdown(
        f"""
        <div class="status-toast">
            <span class="status-toast-dot"></span>
            <span>{status_message}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

deleted_message = st.session_state.pop("report_deleted_message", None)
if deleted_message:
    st.markdown(
        f"""
        <div class="status-toast">
            <span class="status-toast-dot"></span>
            <span>{deleted_message}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

# GLOBAL SEARCH
# -----------------------------------------------------------------------------
if global_query.strip():
    q = global_query.strip().lower()
    matches = []
    for alert in current_alerts:
        haystack = " ".join(str(alert.get(k, "")) for k in [
            "alert_id", "source", "threat_type", "summary", "status", "timestamp"
        ]).lower()
        if q in haystack:
            matches.append(alert)
    render_page_header("SEARCH", f"Results for “{global_query.strip()}”", "Cross-alert lookup across the current SOC dataset.")
    st.markdown(f'<div class="section-title">{len(matches)} matching alert(s)</div>', unsafe_allow_html=True)
    render_alert_table(matches)
    st.stop()


# -----------------------------------------------------------------------------
# PAGE: SOC OVERVIEW
# -----------------------------------------------------------------------------
if app_mode == "SOC Overview":

    render_page_header(
        "COMMAND CENTER",
        "SOC Overview",
        "",
    )

    alerts = get_all_alerts()
    critical = sum(a.get("severity") == "CRITICAL" for a in alerts)
    high = sum(a.get("severity") == "HIGH" for a in alerts)
    open_count = sum(a.get("status") in {"OPEN", "INVESTIGATING"} for a in alerts)
    threats = len(alerts)
    scans = len(runtime_workspace["scan_history"])

    st.markdown('<div class="section-title">Current workload</div>', unsafe_allow_html=True)
    overview_items = [
        ("ACTIVE ALERTS", open_count, "Open + investigating"),
        ("CRITICAL", critical, "Requires immediate review"),
        ("HIGH", high, "Priority triage"),
        ("THREAT DETECTIONS", threats, "Recorded in SQLite"),
    ]
    for label, value, note in overview_items:
        st.markdown(
            f'<div class="overview-metric">'
            f'<div><div class="metric-label">{label}</div><div class="metric-note">{note}</div></div>'
            f'<div class="overview-metric-value">{value}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

    st.markdown('<div class="section-title">Recent alert activity</div>', unsafe_allow_html=True)
    render_alert_table(alerts, limit=8)

    st.markdown('<div class="section-title">Severity distribution</div>', unsafe_allow_html=True)
    sev_counts = pd.DataFrame({
        "Severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        "Alerts": [
            sum(a.get("severity") == "CRITICAL" for a in alerts),
            sum(a.get("severity") == "HIGH" for a in alerts),
            sum(a.get("severity") == "MEDIUM" for a in alerts),
            sum(a.get("severity") == "LOW" for a in alerts),
        ],
    })
    if alerts:
        st.bar_chart(sev_counts, x="Severity", y="Alerts", height=260)
    else:
        st.markdown('<div class="panel"><span class="panel-meta">No alert distribution available.</span></div>', unsafe_allow_html=True)

    st.markdown('<div class="section-title">Session activity</div>', unsafe_allow_html=True)
    if scans:
        st.dataframe(runtime_workspace["scan_history"].tail(8), use_container_width=True, hide_index=True)
    else:
        st.caption("No scans have been executed in this runtime session.")


# -----------------------------------------------------------------------------
# PAGE: ALERTS
# -----------------------------------------------------------------------------
elif app_mode == "Alert Queue":
    render_page_header(
        "OPERATIONS",
        "Alert Queue",
        "",
    )

    alerts = get_all_alerts()
    if alerts:
        df = pd.DataFrame(alerts)
        c1, c2, c3, c4 = st.columns([1.5, 1, 1, 1.4])
        with c1:
            query = st.text_input("Search", placeholder="Alert ID, source, threat type...", label_visibility="collapsed")
        with c2:
            severity = st.selectbox("Severity", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"], label_visibility="collapsed")
        with c3:
            status = st.selectbox("Status", ["ALL", "OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"], label_visibility="collapsed")
        with c4:
            threat_types = ["ALL"] + sorted(df["threat_type"].dropna().astype(str).unique().tolist())
            threat = st.selectbox("Detection", threat_types, label_visibility="collapsed")

        filtered = df.copy()
        if query.strip():
            mask = filtered.astype(str).apply(lambda col: col.str.contains(query, case=False, na=False))
            filtered = filtered[mask.any(axis=1)]
        if severity != "ALL":
            filtered = filtered[filtered["severity"].astype(str).str.upper() == severity]
        if status != "ALL":
            filtered = filtered[filtered["status"].astype(str).str.upper() == status]
        if threat != "ALL":
            filtered = filtered[filtered["threat_type"] == threat]

        render_metric_strip([
            ("Visible", len(filtered), "after filters"),
            ("Critical", int((filtered["severity"] == "CRITICAL").sum()), "current view"),
            ("Open", int(filtered["status"].isin(["OPEN", "INVESTIGATING"]).sum()), "needs analyst action"),
            ("Total", len(df), "all alerts"),
        ])

        st.markdown('<div class="section-title">Detections</div>', unsafe_allow_html=True)
        display_cols = ["alert_id", "timestamp", "source", "threat_type", "severity", "priority", "confidence", "risk_score", "status"]
        display_cols = [c for c in display_cols if c in filtered.columns]
        st.dataframe(
            filtered[display_cols].sort_values("timestamp", ascending=False),
            use_container_width=True,
            hide_index=True,
        )

        st.markdown('<div class="section-title">Alert administration</div>', unsafe_allow_html=True)
        admin1, admin2 = st.columns(2)
        with admin1:
            selected_delete = st.selectbox("Alert", ["— Select alert —"] + filtered["alert_id"].tolist(), key="delete_selection")
            if selected_delete != "— Select alert —":
                if st.button("Delete alert", key="delete_btn"):
                    delete_alert(selected_delete)
                    delete_analyst_notes(selected_delete)
                    st.success(f"{selected_delete} deleted.")
                    st.rerun()
        with admin2:
            retention = st.selectbox("Closed-alert retention", [7, 30, 60, 90], index=1, format_func=lambda x: f"{x} days")
            if st.button("Apply retention cleanup", key="cleanup_btn"):
                count = delete_old_closed_alerts(retention)
                st.info(f"{count} closed alert(s) removed.")
                st.rerun()
    else:
        st.markdown('<div class="empty-state"><div class="empty-title">Alert queue is empty</div><div class="empty-copy">Execute an email or domain analysis to create the first detection.</div></div>', unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# PAGE: INVESTIGATIONS
# -----------------------------------------------------------------------------
elif app_mode == "Incident Investigation":
    render_page_header(
        "OPERATIONS",
        "Incident Investigation",
        "",
    )

    alerts = get_all_alerts()
    if not alerts:
        st.markdown('<div class="empty-state"><div class="empty-title">Nothing to investigate</div><div class="empty-copy">Run a phishing email or high-risk domain analysis first.</div></div>', unsafe_allow_html=True)
    else:
        options = {a["alert_id"]: a for a in alerts}
        selected_id = st.selectbox(
            "Select alert",
            list(options.keys()),
            format_func=lambda x: f'{x}  ·  {options[x].get("severity", "LOW")}  ·  {options[x].get("threat_type", "Alert")}',
        )
        incident = get_alert(selected_id)

        if incident:
            sev = str(incident.get("severity", "LOW"))
            st.markdown(
                f'<div class="panel" style="border-left:3px solid var(--{severity_class(sev).replace("sev-", "") if severity_class(sev) else "low"});">'
                f'<div style="display:flex;justify-content:space-between;gap:20px;align-items:center">'
                f'<div><div class="page-kicker">{incident.get("alert_id", "ALERT")}</div>'
                f'<div style="font-size:1.02rem;font-weight:700;color:#e8eef2">{incident.get("threat_type", "Security Alert")}</div>'
                f'<div style="font-size:.68rem;color:#667582;margin-top:4px">{incident.get("summary", "")}</div></div>'
                f'<div class="sev {severity_class(sev)}" style="font-size:.75rem">{sev}</div>'
                '</div></div>',
                unsafe_allow_html=True,
            )

            st.markdown('<div class="section-title">Case metrics</div>', unsafe_allow_html=True)
            investigation_metrics = [
                ("SEVERITY", incident.get("severity", "—"), "Alert classification"),
                ("PRIORITY", incident.get("priority", "—"), "Response priority"),
                ("RISK SCORE", f'{incident.get("risk_score", 0)}/100', "Calculated risk"),
                ("CONFIDENCE", f'{incident.get("confidence", 0)}%', "Detection confidence"),
            ]
            for label, value, note in investigation_metrics:
                st.markdown(
                    f'<div class="investigation-metric">'
                    f'<div><div class="metric-label">{label}</div><div class="metric-note">{note}</div></div>'
                    f'<div class="investigation-metric-value">{value}</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

            st.markdown('<div class="section-title">Alert evidence</div>', unsafe_allow_html=True)
            evidence_items = [
                ("Alert ID", incident.get("alert_id", "—")),
                ("Source", incident.get("source", "—")),
                ("Threat", incident.get("threat_type", "—")),
                ("Status", incident.get("status", "—")),
                ("Time", incident.get("timestamp", "—")),
            ]
            evidence_html = '<div class="investigation-evidence-row">'
            for label, value in evidence_items:
                evidence_html += (
                    f'<div class="investigation-evidence-item">'
                    f'<span class="detail-label">{label}</span>'
                    f'<span class="detail-value">{value}</span>'
                    f'</div>'
                )
            evidence_html += '</div>'
            st.markdown(evidence_html, unsafe_allow_html=True)

            st.markdown('<div class="section-title">Indicators of compromise</div>', unsafe_allow_html=True)
            st.markdown('<div class="ioc-row">', unsafe_allow_html=True)
            render_iocs(incident.get("indicators", []))
            st.markdown('</div>', unsafe_allow_html=True)

            st.markdown('<div class="section-title">Analyst notes</div>', unsafe_allow_html=True)
            notes_key = f"notes_editor_{selected_id}"
            if notes_key not in st.session_state:
                st.session_state[notes_key] = get_analyst_notes(selected_id)

            analyst_notes = st.text_area(
                "Investigation notes",
                key=notes_key,
                height=150,
                placeholder="Example: Reviewed the extracted IOC, checked the detection signals, and escalated the alert for further review.",
                label_visibility="collapsed",
            )

            if st.button("Save analyst notes", type="primary", key=f"save_notes_{selected_id}"):
                try:
                    save_analyst_notes(selected_id, analyst_notes)
                    saved_notes = get_analyst_notes(selected_id)

                    if saved_notes == analyst_notes.strip():
                        report_row = get_incident_report(selected_id)
                        if report_row:
                            updated_report = update_incident_report_content(
                                report_row.get("report", ""),
                                analyst_notes=saved_notes,
                            )
                            update_incident_report(selected_id, report=updated_report)
                            set_latest_report(updated_report)
                        st.success("Analyst notes saved.")
                        st.caption("The notes are stored with this alert and will appear in its existing incident report.")
                    else:
                        st.error("The notes were saved but could not be verified from SQLite.")
                except Exception as exc:
                    st.error(f"Unable to save analyst notes: {exc}")

            st.markdown('<div class="section-title">Disposition</div>', unsafe_allow_html=True)
            statuses = ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"]
            current = incident.get("status", "OPEN")
            new_status = st.selectbox(
                "Status",
                statuses,
                index=statuses.index(current) if current in statuses else 0,
                key=f"status_{selected_id}",
            )
            if st.button("Save disposition", type="primary", key=f"save_status_{selected_id}"):
                try:
                    # Persist the alert status first, then verify the database contains the new value.
                    update_alert_status(selected_id, new_status)
                    persisted_alert = get_alert(selected_id)
                    persisted_status = str((persisted_alert or {}).get("status", "")).upper()
                    if persisted_status != str(new_status).upper():
                        raise RuntimeError(
                            f"Database verification failed: expected {new_status}, found {persisted_status or 'UNKNOWN'}."
                        )

                    report_row = get_incident_report(selected_id)
                    if report_row:
                        updated_report = update_incident_report_content(
                            report_row.get("report", ""),
                            status=new_status,
                        )
                        update_incident_report(
                            selected_id,
                            report=updated_report,
                            status=new_status,
                        )
                        set_latest_report(updated_report)

                    incident["status"] = new_status
                    status_message = (
                        f"STATUS UPDATED · {selected_id}: {current} → {new_status}."
                        if current != new_status
                        else f"STATUS UPDATED · {selected_id} remains {new_status}."
                    )
                    st.markdown(
                        f"""
                        <div class="status-toast status-toast-inline">
                            <span class="status-toast-dot"></span>
                            <span>{status_message}</span>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                except Exception as exc:
                    st.error(f"Unable to save disposition: {exc}")


# -----------------------------------------------------------------------------
# PAGE: EMAIL SECURITY
# -----------------------------------------------------------------------------
elif app_mode == "Email Security":
    render_page_header(
        "DETECTION",
        "Email Security",
        "",
    )

    if runtime_workspace["email_result"] is not None:
        default_email = runtime_workspace["email_result"]["input"]
    else:
        default_email = ""

    # Primary analyst input: intentionally kept as one large paste area.
    st.markdown('<div class="section-title">Email payload</div>', unsafe_allow_html=True)
    email_text = st.text_area(
        "Paste email",
        value=default_email,
        height=260,
        placeholder="From: security@example.com\nSubject: Suspicious account activity\n\nPaste the complete email content here...",
        label_visibility="collapsed",
        key="email_editor",
    )

    analyze = st.button(
        "Analyze email",
        type="primary",
        use_container_width=True,
        key="analyze_email",
    )
    clear = st.button(
        "Clear workspace",
        use_container_width=True,
        key="clear_email",
    )


    if clear:
        runtime_workspace["email_result"] = None
        st.session_state.pop("email_editor", None)
        st.rerun()

    if analyze:
        if not email_text.strip():
            st.warning("Paste an email message before running the analysis.")
        elif email_model is None:
            st.error("The phishing model assets could not be loaded from the models directory.")
        else:
            cleaned = clean_text(email_text)
            vector = vectorizer.transform([cleaned])
            prediction = email_model.predict(vector)[0]
            probabilities = email_model.predict_proba(vector)[0]
            confidence = round(float(max(probabilities)) * 100, 2)
            prediction_label = "Phishing" if prediction == 1 else "Legitimate"

            suspicious_words = [
                "urgent", "verify", "password", "bank", "account",
                "click", "login", "suspended", "payment", "security",
            ]
            matched_words = [word for word in suspicious_words if word in cleaned]
            iocs = extract_iocs(email_text)
            ioc_labels = [f"{key}: {len(values)}" for key, values in iocs.items() if values]
            sender, subject, has_links, has_attachments = extract_email_metadata(email_text)

            email_alert = None
            if prediction == 1:
                email_alert = add_security_alert(
                    source="Email Analyzer",
                    threat_type="Credential Phishing",
                    confidence=confidence,
                    risk_score=int(confidence),
                    indicators=matched_words + ioc_labels,
                    summary="ML phishing detection triggered a SOC alert.",
                )
                verdict = "PHISHING DETECTED"
            else:
                verdict = "LEGITIMATE"

            add_history_record("Email Payload", email_text, f"{confidence}%", verdict)

            with st.spinner("Running AI security assessment..."):
                analysis = generate_threat_analysis(
                    email_text=email_text,
                    prediction=prediction_label,
                    sender=sender,
                    subject=subject,
                    has_links=has_links,
                    has_attachments=has_attachments,
                )
                report = generate_incident_report(
                    analysis=analysis,
                    analysis_type="Email Analysis",
                    threat_level=prediction_label,
                    threat_type=prediction_label,
                    risk_score=f"{confidence}%",
                )

            email_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            email_severity, _email_priority = severity_from_score(confidence if prediction == 1 else 0)

            runtime_workspace["email_result"] = {
                "input": email_text,
                "prediction": prediction_label,
                "confidence": confidence,
                "matched_words": matched_words,
                "iocs": iocs,
                "ioc_labels": ioc_labels,
                "sender": sender,
                "subject": subject,
                "has_links": has_links,
                "has_attachments": has_attachments,
                "analysis": analysis,
                "incident_report": report,
                "timestamp": email_timestamp,
            }
            set_latest_report(report)

            if prediction == 1:
                save_incident_report(
                    title=f"Email Security Incident · {email_severity}",
                    source="Email Analyzer",
                    severity=email_severity,
                    verdict=prediction_label,
                    timestamp=email_timestamp,
                    report=report,
                    alert_id=email_alert.get("alert_id") if email_alert else None,
                    status=email_alert.get("status", "OPEN") if email_alert else "OPEN",
                )

                alert_reports = runtime_workspace.setdefault("incident_reports", [])
                alert_reports.insert(0, {
                    "title": f"Email Security Incident · {email_severity}",
                    "alert_id": email_alert.get("alert_id") if email_alert else None,
                    "source": "Email Analyzer",
                    "severity": email_severity,
                    "verdict": prediction_label,
                    "timestamp": email_timestamp,
                    "report": report,
                })

            st.rerun()

    result = runtime_workspace["email_result"]
    if result:
        prediction = result["prediction"]
        sev, _priority = severity_from_score(result["confidence"] if prediction == "Phishing" else 0)

        st.markdown('<div class="section-title">Assessment</div>', unsafe_allow_html=True)
        verdict_class = "severity-word-high" if prediction == "Phishing" else "severity-word-low"
        st.markdown(
            f'<div class="severity-banner {"severity-high" if prediction == "Phishing" else "severity-low"}">'
            f'<span class="severity-dot"></span>'
            f'<div><div class="detail-label">OVERALL EMAIL PRIORITY</div>'
            f'<div class="{verdict_class}" style="font-size:1.15rem;font-weight:800">{prediction.upper()}</div>'
            f'</div></div>',
            unsafe_allow_html=True,
        )
        render_metric_strip([
            ("Confidence", f'{result["confidence"]}%', "model confidence"),
            ("IOCs", len(result["ioc_labels"]), "extracted indicators"),
            ("Matched terms", len(result["matched_words"]), "language signals"),
            ("Analyzed", result["timestamp"][-8:], "local runtime"),
        ])

        # Keep detection evidence factual and compact.
        st.markdown('<div class="section-title">Detection evidence</div>', unsafe_allow_html=True)

        sev_key = sev.lower()
        st.markdown(
            f'<div class="severity-banner severity-{sev_key}">'
            f'<span class="severity-dot"></span>'
            f'<div><div class="detail-label">DETECTION PRIORITY</div>'
            f'<div class="severity-word-{sev_key}" style="font-size:1.05rem;font-weight:800;letter-spacing:.04em">{sev}</div>'
            f'</div></div>',
            unsafe_allow_html=True,
        )

        with st.container(border=True):
            st.markdown("**Matched language**")
            render_iocs(result["matched_words"])
            st.markdown("**Extracted IOCs**")
            render_iocs(result["ioc_labels"])

        with st.container(border=True):
            st.markdown("**Message metadata**")
            for label, value in [
                ("SENDER", result.get("sender", "Not provided")),
                ("SUBJECT", result.get("subject", "Not provided")),
                ("LINKS", result.get("has_links", "Unknown")),
                ("ATTACHMENTS", result.get("has_attachments", "Unknown")),
            ]:
                st.caption(label)
                st.write(value)

        # AI is deliberately separated from the ML result.
        st.markdown('<div class="section-title">AI analyst review</div>', unsafe_allow_html=True)
        with st.container(border=True):
            st.markdown(result["analysis"])

    else:
        st.markdown(
            '<div class="empty-state">'
            '<div class="empty-title">Ready for email analysis</div>'
            '</div></div>',
            unsafe_allow_html=True,
        )


# PAGE: DOMAIN SECURITY
# -----------------------------------------------------------------------------
elif app_mode == "Domain Security":
    render_page_header(
        "DETECTION",
        "Domain Security",
        "",
    )

    default_url = (
        runtime_workspace["website_result"]["input"]
        if runtime_workspace["website_result"] is not None
        else ""
    )

    st.markdown('<div class="section-title">URL payload</div>', unsafe_allow_html=True)
    url = st.text_input(
        "URL",
        value=default_url,
        placeholder="https://example.com/login",
        label_visibility="collapsed",
        key="domain_editor",
    )

    scan = st.button(
        "Scan domain",
        type="primary",
        use_container_width=True,
        key="scan_domain",
    )
    clear = st.button(
        "Clear workspace",
        use_container_width=True,
        key="clear_domain",
    )


    if clear:
        runtime_workspace["website_result"] = None
        st.session_state.pop("domain_editor", None)
        st.rerun()

    if scan:
        if not url.strip():
            st.warning("Enter a URL before running the domain assessment.")
        else:
            score, reasons = analyze_url(url.strip())
            verdict = "High Risk" if score >= 65 else "Suspicious" if score >= 40 else "Low Risk"
            result = {
                "score": score,
                "reasons": reasons,
                "input": url.strip(),
                "verdict": verdict,
            }

            # Medium-or-higher domain findings become SOC alerts.
            website_alert = None
            if score >= 40:
                website_alert = add_security_alert(
                    source="Domain Integrity Scanner",
                    threat_type="Suspicious Website",
                    confidence=float(score),
                    risk_score=int(score),
                    indicators=reasons,
                    summary="Suspicious domain characteristics detected.",
                )

            add_history_record(
                "Domain Payload",
                url.strip(),
                f"{score}/100",
                verdict,
            )

            with st.spinner("Running AI website security assessment..."):
                analysis = generate_website_analysis(
                    url.strip(),
                    score,
                    reasons,
                    verdict,
                )
                report = generate_incident_report(
                    analysis=analysis,
                    analysis_type="Domain Analysis",
                    threat_level=verdict,
                    threat_type="Suspicious Website" if score >= 40 else "Domain Security Review",
                    risk_score=f"{score}/100",
                )

            result["analysis"] = analysis
            result["incident_report"] = report
            result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            runtime_workspace["website_result"] = result
            set_latest_report(report)

            if score >= 40:
                website_severity, _website_priority = severity_from_score(score)

                save_incident_report(
                    title=f"Domain Security Incident · {website_severity}",
                    source="Domain Integrity Scanner",
                    severity=website_severity,
                    verdict=verdict,
                    timestamp=result["timestamp"],
                    report=report,
                    alert_id=website_alert.get("alert_id") if website_alert else None,
                    status=website_alert.get("status", "OPEN") if website_alert else "OPEN",
                )

                alert_reports = runtime_workspace.setdefault("incident_reports", [])
                alert_reports.insert(0, {
                    "title": f"Domain Security Incident · {website_severity}",
                    "alert_id": website_alert.get("alert_id") if website_alert else None,
                    "source": "Domain Integrity Scanner",
                    "severity": website_severity,
                    "verdict": verdict,
                    "timestamp": result["timestamp"],
                    "report": report,
                })

            st.rerun()

    result = runtime_workspace["website_result"]

    if result:
        score = int(result["score"])
        verdict = str(result["verdict"])
        sev = "CRITICAL" if score >= 85 else "HIGH" if score >= 65 else "MEDIUM" if score >= 40 else "LOW"
        sev_key = sev.lower()

        st.markdown('<div class="section-title">Assessment</div>', unsafe_allow_html=True)
        st.markdown(
            f'<div class="severity-banner severity-{sev_key}">'
            f'<span class="severity-dot"></span>'
            f'<div><div class="detail-label">OVERALL DOMAIN PRIORITY</div>'
            f'<div class="severity-word-{sev_key}" style="font-size:1.15rem;font-weight:800">{sev}</div>'
            f'</div></div>',
            unsafe_allow_html=True,
        )

        render_metric_strip([
            ("Risk score", f"{score}/100", "heuristic score"),
            ("Indicators", len(result.get("reasons", [])), "detected signals"),
            ("Verdict", verdict.upper(), "detector output"),
            ("Analyzed", result["timestamp"][-8:], "local runtime"),
        ])

        st.markdown('<div class="section-title">Detection evidence</div>', unsafe_allow_html=True)

        st.markdown(
            f'<div class="severity-banner severity-{sev_key}">'
            f'<span class="severity-dot"></span>'
            f'<div><div class="detail-label">DETECTION PRIORITY</div>'
            f'<div class="severity-word-{sev_key}" style="font-size:1.05rem;font-weight:800;letter-spacing:.04em">{sev}</div>'
            f'</div></div>',
            unsafe_allow_html=True,
        )

        with st.container(border=True):
            st.markdown("**Heuristic indicators**")
            render_iocs(result.get("reasons", []))
            st.markdown("**Target URL**")
            st.code(result["input"], language=None)

        with st.container(border=True):
            st.markdown("**URL metadata**")
            for label, value in [
                ("RISK SCORE", f"{score}/100"),
                ("VERDICT", verdict),
                ("INDICATORS", len(result.get("reasons", []))),
                ("ENGINE", "URL heuristic engine"),
            ]:
                st.caption(label)
                st.write(value)
            st.progress(score)

        # Same AI section treatment as Email Security.
        st.markdown('<div class="section-title">AI analyst review</div>', unsafe_allow_html=True)
        with st.container(border=True):
            st.markdown(result["analysis"])

    else:
        st.markdown(
            '<div class="empty-state">'
            '<div class="empty-title">Ready for domain analysis</div>'
            '</div></div>',
            unsafe_allow_html=True,
        )


# PAGE: REPORTS
# -----------------------------------------------------------------------------
elif app_mode == "Incident Reporting":
    render_page_header(
        "OPERATIONS",
        "Incident Reporting",
        "",
    )

    # -------------------------------------------------------------------------
    # DATABASE STATUS
    # -------------------------------------------------------------------------
    stats = get_database_stats()

    st.markdown(
        '<div class="section-title">SOC Data Management</div>',
        unsafe_allow_html=True,
    )

    m1, m2, m3 = st.columns(3)
    m1.metric("SOC Alerts", stats["alerts"])
    m2.metric("Incident Reporting", stats["reports"])
    m3.metric("Analyst Notes", stats["notes"])

    # -------------------------------------------------------------------------
    # EXPORT ALERT REGISTER
    # -------------------------------------------------------------------------
    alerts = get_all_alerts()
    if alerts:
        df = pd.DataFrame(alerts)
        export_cols = [
            "alert_id", "timestamp", "source", "threat_type", "severity",
            "priority", "confidence", "risk_score", "status", "summary"
        ]
        export_cols = [c for c in export_cols if c in df.columns]
        csv_data = df[export_cols].to_csv(index=False).encode("utf-8")

        st.download_button(
            "Export SOC Alert Register (CSV)",
            csv_data,
            file_name=f"cybershield_alerts_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
            mime="text/csv",
            use_container_width=True,
            key="export_alert_register",
        )

    # -------------------------------------------------------------------------
    # ADMINISTRATIVE RESET
    # -------------------------------------------------------------------------
    st.markdown(
        '<div class="section-title">Administrative Data Reset</div>',
        unsafe_allow_html=True,
    )

    with st.expander("Clear SOC Workspace"):
        st.warning(
            "This permanently deletes all SOC alerts, incident reports and "
            "analyst notes. Your ML model, datasets and application code "
            "will not be affected."
        )

        confirm_reset = st.checkbox(
            "I understand that this action cannot be undone.",
            key="confirm_soc_reset",
        )

        if st.button(
            "Clear All SOC Data",
            type="primary",
            disabled=not confirm_reset,
            use_container_width=True,
            key="clear_all_soc_data",
        ):
            try:
                clear_all_soc_data()

                runtime_workspace["scan_history"] = pd.DataFrame(
                    columns=[
                        "Timestamp", "Target Type", "Input Preview",
                        "Risk Score / Confidence", "Verdict"
                    ]
                )
                runtime_workspace["email_result"] = None
                runtime_workspace["website_result"] = None
                runtime_workspace["latest_incident_report"] = None
                runtime_workspace["incident_reports"] = []

                for key in [
                    "latest_incident_report",
                    "confirm_soc_reset",
                ]:
                    st.session_state.pop(key, None)

                st.success(
                    "All SOC alerts, incident reports and analyst notes have been cleared."
                )
                st.rerun()

            except Exception as exc:
                st.error(f"Unable to clear SOC data: {exc}")

    # -------------------------------------------------------------------------
    # PERSISTENT INCIDENT REPORT HISTORY
    # -------------------------------------------------------------------------
    st.markdown(
        '<div class="section-title">Incident Report History</div>',
        unsafe_allow_html=True,
    )

    deleted_message = st.session_state.pop("report_deleted_message", None)
    if deleted_message:
        st.success(deleted_message)

    # SQLite is the source of truth. Do not fall back to only the latest report.
    reports = get_all_incident_reports()

    if reports:
        st.caption(f"{len(reports)} incident report(s) stored in the SOC database.")

        for idx, item in enumerate(reports):
            report_text = str(item.get("report", ""))
            source = str(item.get("source", "SOC"))
            title = str(item.get("title", "Incident Report"))
            verdict = str(item.get("verdict", "Security Incident"))
            timestamp = str(item.get("timestamp", ""))
            report_id = item.get("report_id", idx + 1)
            alert_id = str(item.get("alert_id") or "—")

            raw_score = item.get("risk_score")
            if raw_score is None:
                match = re.search(
                    r"Risk Score\*?\*?\s*\|\s*\*?\*?([0-9]+(?:\.[0-9]+)?)",
                    report_text,
                    re.I,
                )
                raw_score = match.group(1) if match else 0

            score_match = re.search(r"[0-9]+(?:\.[0-9]+)?", str(raw_score))
            score = float(score_match.group()) if score_match else 0.0
            severity, priority = severity_from_score(score)

            severity_class_name = severity.lower()

            with st.container(border=True):
                st.markdown(
                    f'<div class="report-entry-header">'
                    f'<div><div class="report-entry-title">{title}</div>'
                    f'<div class="report-entry-meta">Alert ID {alert_id} · {source} · {timestamp}</div></div>'
                    f'<div class="severity-word-{severity_class_name}">{severity} · {priority}</div></div>',
                    unsafe_allow_html=True,
                )

                c1, c2, c3, c4, c5 = st.columns(5)
                metric_items = [
                    (c1, "Threat", verdict),
                    (c2, "Severity", severity),
                    (c3, "Risk Score", f"{score:g}/100"),
                    (c4, "Status", str(item.get("status", "OPEN")).upper()),
                    (c5, "Source", source),
                ]
                for col, label, value in metric_items:
                    with col:
                        value_class = "report-metric-value severity" if label == "Severity" else "report-metric-value"
                        st.markdown(
                            f'<div class="report-metric"><div class="report-metric-label">{label}</div>'
                            f'<div class="{value_class}">{value}</div></div>',
                            unsafe_allow_html=True,
                        )

                with st.expander("Open Full Incident Report", expanded=False):
                    st.markdown('<div class="report-report-body">', unsafe_allow_html=True)
                    st.markdown(report_text)

                with st.container(key=f"reportactions_{report_id}"):
                    action_col1, action_col2 = st.columns([1, 1], gap="small")

                    with action_col1:
                        try:
                            pdf_path = create_incident_pdf(report_text)
                            with open(pdf_path, "rb") as pdf_file:
                                st.download_button(
                                    "Download PDF Report",
                                    pdf_file.read(),
                                    file_name=f"AI_CyberShield_Incident_Report_{alert_id}.pdf",
                                    mime="application/pdf",
                                    use_container_width=True,
                                    key=f"download_incident_report_{report_id}",
                                )
                        except Exception as exc:
                            st.warning(f"The PDF report could not be generated: {exc}")

                    with action_col2:
                        if st.button(
                            "Delete Report",
                            use_container_width=True,
                            key=f"delete_incident_report_{report_id}",
                        ):
                            try:
                                if delete_incident_report_local(report_id):
                                    st.session_state["report_deleted_message"] = (
                                        f"REPORT DELETED · Incident report for {alert_id} removed."
                                    )
                                else:
                                    st.session_state["report_deleted_message"] = (
                                        "REPORT DELETE FAILED · Incident report was not found."
                                    )
                            except Exception as exc:
                                st.session_state["report_deleted_message"] = (
                                    f"REPORT DELETE FAILED · {exc}"
                                )
                            st.rerun()
                    st.markdown('</div>', unsafe_allow_html=True)

    else:
        st.markdown(
            '<div class="empty-state"><div class="empty-title">No security incident reports</div>'
            '<div class="empty-copy">Run an email or domain security analysis to generate a report.</div></div>',
            unsafe_allow_html=True,
        )

# -----------------------------------------------------------------------------
# FOOTER
# -----------------------------------------------------------------------------
st.markdown(
    '<div style="border-top:1px solid #17222d;margin-top:32px;padding:12px 0 4px;display:flex;justify-content:space-between;color:#4f5e6b;font-size:.61rem;letter-spacing:.03em">'
    '<span>AI CYBERSHIELD · SECURITY OPERATIONS CONSOLE</span>'
    '<span>ANALYST WORKSPACE</span>'
    '</div>',
    unsafe_allow_html=True,
)
