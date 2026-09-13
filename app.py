import re
from datetime import datetime

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

/* Global shell */
.topbar {
    height: 54px;
    border-bottom: 1px solid var(--line-soft);
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin: -1rem -1rem 22px;
    padding: 0 20px;
    background: rgba(10,15,20,.94);
}
.topbar-left { display: flex; align-items: center; gap: 13px; }
.topbar-title { color: #dce5eb; font-size: .88rem; font-weight: 650; letter-spacing: .06em; }
.topbar-context { color: #596875; font-size: .76rem; }
.system-state { color: #6fc19d; font-size: .76rem; font-weight: 700; letter-spacing: .09em; }
.state-dot { display:inline-block; width:6px; height:6px; border-radius:50%; background:#64b990; margin-right:7px; }

.page-kicker {
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
    margin: 0;
}
.page-description { color: var(--muted); font-size: .90rem; margin: 7px 0 20px; }

.section-title {
    color: #cbd5de;
    font-size: .82rem;
    font-weight: 720;
    letter-spacing: .08em;
    text-transform: uppercase;
    margin: 19px 0 9px;
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

div[data-testid="stExpander"] { background:var(--surface); border:1px solid var(--line); border-radius:4px; }
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


def render_page_header(kicker, title, description):
    st.markdown(f'<div class="page-kicker">{kicker}</div>', unsafe_allow_html=True)
    st.markdown(f'<h1 class="page-title">{title}</h1>', unsafe_allow_html=True)
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


# -----------------------------------------------------------------------------
# APPLICATION SHELL
# -----------------------------------------------------------------------------
try:
    current_alerts = get_all_alerts()
    db_state = "ONLINE"
except Exception:
    current_alerts = []
    db_state = "UNAVAILABLE"

with st.sidebar:
    st.markdown('<div class="brand">🛡️ AI CYBERSHIELD</div>', unsafe_allow_html=True)
    st.markdown('<div class="brand-sub">Security Operations Console</div><div class="brand-sub" style="margin-top:7px;color:#657887;letter-spacing:.05em;text-transform:none;">Detect · Triage · Investigate · Resolve</div>', unsafe_allow_html=True)

    st.markdown('<div class="nav-label">Operations</div>', unsafe_allow_html=True)
    app_mode = st.radio(
        "Workspace",
        [
            "🛡️  SOC Overview",
            "🚨  Alerts",
            "🔎  Investigations",
            "✉️  Email Security",
            "🌐  Domain Security",
            "📄  Reports",
        ],
        label_visibility="collapsed",
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
        f'<div>DETECTION ENGINE <strong>{"READY" if email_model is not None else "UNAVAILABLE"}</strong></div>'
        f'<div>ALERTS <strong>{len(current_alerts)}</strong></div>'
        f'<div>SESSION SCANS <strong>{len(runtime_workspace["scan_history"])}</strong></div>'
        '</div>',
        unsafe_allow_html=True,
    )

st.markdown(
    '<div class="topbar">'
    '<div class="topbar-left"><span class="topbar-title">AI CYBERSHIELD</span>'
    '<span class="topbar-context">/ SOC WORKSPACE</span></div>'
    '<div class="system-state"><span class="state-dot"></span>DATABASE / DETECTION STATUS</div>'
    '</div>',
    unsafe_allow_html=True,
)

if st.session_state.pop("flash_success", None):
    st.success(st.session_state.pop("flash_success_text", "Saved successfully."))


# -----------------------------------------------------------------------------
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
if app_mode.endswith("SOC Overview"):

    render_page_header(
        "COMMAND CENTER",
        "SOC Overview",
        "A compact view of the current security workload, active investigations and recent detections.",
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

    st.markdown('<div class="section-title">Investigation workflow</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="workflow workflow-vertical">'
        '<div class="workflow-item active"><span class="workflow-num">01</span>DETECT</div>'
        '<div class="workflow-item active"><span class="workflow-num">02</span>TRIAGE</div>'
        '<div class="workflow-item"><span class="workflow-num">03</span>INVESTIGATE</div>'
        '<div class="workflow-item"><span class="workflow-num">04</span>CONTAIN</div>'
        '<div class="workflow-item"><span class="workflow-num">05</span>RESOLVE</div>'
        '</div>',
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
elif app_mode.endswith("Alerts"):
    render_page_header(
        "OPERATIONS / ALERTS",
        "Alert Queue",
        "Review, filter and route detections generated by the email and domain security engines.",
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
elif app_mode.endswith("Investigations"):
    render_page_header(
        "OPERATIONS / INVESTIGATION",
        "Incident Investigation",
        "Move from detection evidence to an analyst decision without leaving the alert record.",
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

            st.markdown('<div class="section-title">Case workflow</div>', unsafe_allow_html=True)
            status = str(incident.get("status", "OPEN")).upper()
            stage = 1 if status == "OPEN" else 2 if status == "INVESTIGATING" else 3 if status == "CONTAINED" else 4
            labels = ["DETECT", "TRIAGE", "INVESTIGATE", "CONTAIN", "RESOLVE"]
            workflow = '<div class="workflow">'
            for i, label in enumerate(labels, 1):
                workflow += f'<div class="workflow-item {"active" if i <= stage else ""}"><span class="workflow-num">0{i}</span>{label}</div>'
            workflow += '</div>'
            st.markdown(workflow, unsafe_allow_html=True)

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
            st.caption(incident.get("summary", "No detection summary recorded."))

            st.markdown('<div class="section-title">Indicators of compromise</div>', unsafe_allow_html=True)
            st.markdown('<div class="ioc-row">', unsafe_allow_html=True)
            render_iocs(incident.get("indicators", []))
            st.markdown('</div>', unsafe_allow_html=True)

            st.markdown('<div class="section-title">Analyst notes</div>', unsafe_allow_html=True)
            st.caption("Record observations, investigation steps, evidence reviewed, or the reason for the current disposition.")
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
                    update_alert_status(selected_id, new_status)

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

                    st.session_state["flash_success"] = True
                    st.session_state["flash_success_text"] = (
                        f"Disposition saved — {selected_id} is now {new_status}."
                    )
                    st.rerun()
                except Exception as exc:
                    st.error(f"Unable to save disposition: {exc}")


# -----------------------------------------------------------------------------
# PAGE: EMAIL SECURITY
# -----------------------------------------------------------------------------
elif app_mode.endswith("Email Security"):
    render_page_header(
        "DETECTION / EMAIL",
        "Email Security",
        "Paste a complete email message to run phishing detection, IOC extraction and analyst-level AI review.",
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
        placeholder=(
            "Paste the complete message here — From, To, Subject, body, links and any "
            "attachment references if available."
        ),
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

    st.caption(
        "The message is analyzed as supplied. The ML verdict is one detection signal; "
        "IOC evidence and AI review are shown separately so an analyst can compare them."
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
        overall_key = sev.lower()
        verdict_class = f"severity-word-{overall_key}"
        st.markdown(
            f'<div class="severity-banner severity-{overall_key}">'
            f'<span class="severity-dot"></span>'
            f'<div><div class="detail-label">OVERALL EMAIL PRIORITY</div>'
            f'<div class="{verdict_class}" style="font-size:1.15rem;font-weight:800">{sev}</div>'
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
            st.caption("Signals found directly in the pasted message.")
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
            st.caption(
                "AI enrichment is supporting evidence. It does not replace the ML result "
                "or analyst judgement."
            )
            st.markdown(result["analysis"])

    else:
        st.markdown(
            '<div class="empty-state">'
            '<div class="empty-title">Ready for email analysis</div>'
            '<div class="empty-copy">'
            'Paste a complete message above. No sender, subject or separate URL fields are required.'
            '</div></div>',
            unsafe_allow_html=True,
        )


# PAGE: DOMAIN SECURITY
# -----------------------------------------------------------------------------
elif app_mode.endswith("Domain Security"):
    render_page_header(
        "DETECTION / WEB",
        "Domain Security",
        "Paste a URL to assess its structure, extract indicators and obtain an independent AI web-security review.",
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

    st.caption(
        "The URL structure is assessed by the heuristic detector. "
        "AI enrichment is a separate analyst review based on the detected evidence."
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
                    summary="URL heuristic analysis identified suspicious domain characteristics.",
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
            st.caption("Signals found directly in the submitted URL.")
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
            st.caption(
                "AI enrichment is supporting evidence. It does not replace the "
                "heuristic result or analyst judgement."
            )
            st.markdown(result["analysis"])

    else:
        st.markdown(
            '<div class="empty-state">'
            '<div class="empty-title">Ready for domain analysis</div>'
            '<div class="empty-copy">'
            'Paste a URL above to inspect its structure and generate a SOC-style assessment.'
            '</div></div>',
            unsafe_allow_html=True,
        )


# PAGE: REPORTS
# -----------------------------------------------------------------------------
elif app_mode.endswith("Reports"):
    render_page_header(
        "OPERATIONS / REPORTING",
        "Reports",
        "Review persistent incident reports and manage the SOC workspace data.",
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
    m2.metric("Incident Reports", stats["reports"])
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

    with st.expander("⚠️ Clear SOC Workspace"):
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
            "🗑️ Clear All SOC Data",
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
                    f'<div class="report-entry-meta">Report ID {report_id} · {source} · {timestamp}</div></div>'
                    f'<div class="severity-word-{severity_class_name}">{severity} · {priority}</div></div>',
                    unsafe_allow_html=True,
                )

                report_status = str(item.get("status", "OPEN")).upper()
                c1, c2, c3, c4, c5 = st.columns(5)
                c1.metric("Threat", verdict)
                c2.metric("Severity", severity)
                c3.metric("Risk Score", f"{score:g}/100")
                c4.metric("Status", report_status)
                c5.metric("Source", source)

                with st.expander("Open Full Incident Report", expanded=(idx == 0)):
                    st.markdown(report_text)

                try:
                    pdf_path = create_incident_pdf(report_text)
                    with open(pdf_path, "rb") as pdf_file:
                        st.download_button(
                            "📥 Download PDF Report",
                            pdf_file.read(),
                            file_name=f"AI_CyberShield_Incident_Report_{report_id}.pdf",
                            mime="application/pdf",
                            use_container_width=True,
                            key=f"download_incident_report_{report_id}",
                        )
                except Exception as exc:
                    st.warning(f"The PDF report could not be generated: {exc}")

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
