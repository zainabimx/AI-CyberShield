import streamlit as st
import joblib
import re
import pandas as pd
from datetime import datetime
from src.security_core import extract_iocs, create_alert
from src.database import (
    save_alert,
    get_all_alerts,
    get_alert,
    update_alert_status,
    delete_alert,
    delete_old_closed_alerts
)
from llm import (
    generate_threat_analysis,
    generate_website_analysis,
)
from report_generator import generate_incident_report
from pdf_generator import create_incident_pdf

# =====================================
# PAGE SETUP & CONFIGURATION
# =====================================
st.set_page_config(
    page_title="AI CyberShield | Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# =====================================
# RUNTIME WORKSPACE STATE
# =====================================
# This store lives for the lifetime of the Streamlit server process.
# It survives page navigation and browser refreshes, but is recreated
# when the Streamlit application is fully restarted.
@st.cache_resource
def get_runtime_workspace():
    # SOC alerts are intentionally session-lifetime data for this local app.
    # Clear any SQLite alerts left from the previous server run once, at startup.
    try:
        for existing_alert in get_all_alerts():
            delete_alert(existing_alert["alert_id"])
    except Exception:
        # Keep the UI available even if the database is temporarily unavailable.
        pass

    return {
        "scan_history": pd.DataFrame(columns=[
            "Timestamp",
            "Target Type",
            "Input Preview",
            "Risk Score / Confidence",
            "Verdict"
        ]),
        "email_result": None,
        "website_result": None,
        "latest_incident_report": None,
    }


runtime_workspace = get_runtime_workspace()


def add_history_record(target_type, target_input, score, verdict):
    preview = target_input[:40] + "..." if len(target_input) > 40 else target_input
    new_record = pd.DataFrame([{
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Target Type": target_type,
        "Input Preview": preview,
        "Risk Score / Confidence": score,
        "Verdict": verdict
    }])

    runtime_workspace["scan_history"] = pd.concat(
        [runtime_workspace["scan_history"], new_record],
        ignore_index=True
    )


def clear_runtime_workspace(clear_soc=True):
    runtime_workspace["scan_history"] = pd.DataFrame(columns=[
        "Timestamp",
        "Target Type",
        "Input Preview",
        "Risk Score / Confidence",
        "Verdict"
    ])
    runtime_workspace["email_result"] = None
    runtime_workspace["website_result"] = None
    runtime_workspace["latest_incident_report"] = None

    if clear_soc:
        try:
            for existing_alert in get_all_alerts():
                delete_alert(existing_alert["alert_id"])
        except Exception:
            pass

    for key in [
        "email_input_area",
        "url_input_field",
        "analysis",
        "prediction",
        "latest_incident_report",
    ]:
        st.session_state.pop(key, None)


def add_security_alert(
    source,
    threat_type,
    confidence,
    risk_score,
    indicators,
    summary
):
    alert = create_alert(
        source=source,
        threat_type=threat_type,
        confidence=confidence,
        risk_score=risk_score,
        indicators=indicators,
        summary=summary
    )

    save_alert(alert)
    return alert

# =====================================
# PREMIUM PRODUCTION-GRADE UI STYLING
# =====================================
st.markdown("""
<style>
    /* Global Application Canvas */
    .stApp {
        background: radial-gradient(circle at 50% 10%, #131926 0%, #080b11 80%);
        font-family: 'Inter', -apple-system, sans-serif;
    }
    
    /* ULTRA-PREMIUM SIDEBAR NAV OVERRIDE */
    [data-testid="stSidebar"] {
        background-color: #0b0e14 !important;
        border-right: 1px solid rgba(255, 255, 255, 0.05);
    }
    
    /* Target the container for standard radio items */
    [data-testid="stSidebar"] div[role="radiogroup"] {
        gap: 12px;
    }
    
    /* Transform native radio options into beautiful full-width block buttons */
    [data-testid="stSidebar"] div[role="radiogroup"] label {
        background: rgba(255, 255, 255, 0.02);
        border: 1px solid rgba(255, 255, 255, 0.05);
        padding: 14px 18px !important;
        border-radius: 12px !important;
        color: #94A3B8 !important;
        transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
        width: 100%;
        cursor: pointer;
        display: flex !important;
        align-items: center;
    }
    
    /* FORCE HIDE THE SELECTION RADIO CIRCLES COMPLETELY */
    [data-testid="stSidebar"] div[role="radiogroup"] label [data-testid="stWidgetSelectedIndicator"],
    [data-testid="stSidebar"] div[role="radiogroup"] label div:first-child:not([data-testid="stMarkdownContainer"]) {
        display: none !important;
        visibility: hidden !important;
        width: 0px !important;
        height: 0px !important;
        margin: 0px !important;
        padding: 0px !important;
    }
    
    /* Font formatting inside the cleaned options */
    [data-testid="stSidebar"] div[role="radiogroup"] label div[data-testid="stMarkdownContainer"] p {
        font-weight: 500 !important;
        font-size: 0.95rem !important;
        margin: 0 !important;
        padding: 0 !important;
    }
    
    /* Hover state: Clean illumination and elegant scale enlargement */
    [data-testid="stSidebar"] div[role="radiogroup"] label:hover {
        background: rgba(0, 240, 255, 0.05) !important;
        border-color: rgba(0, 240, 255, 0.2) !important;
        color: #E2E8F0 !important;
        transform: scale(1.03);
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
    }
    
    /* Active / Selected option state */
    [data-testid="stSidebar"] div[role="radiogroup"] label[data-checked="true"] {
        background: linear-gradient(135deg, rgba(0, 240, 255, 0.15) 0%, rgba(0, 114, 255, 0.15) 100%) !important;
        border-color: #00F0FF !important;
        color: #00F0FF !important;
        box-shadow: 0 0 15px rgba(0, 240, 255, 0.1);
        transform: scale(1.01);
    }

    /* System Workspace Typography */
    .main-title {
        font-size: 3rem;
        font-weight: 800;
        background: linear-gradient(135deg, #00F0FF 0%, #0072FF 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 2px;
    }
    
    .sub-title {
        color: #6C7A9C;
        font-size: 1.1rem;
        margin-bottom: 25px;
    }
    
    .panel-header {
        color: #E2E8F0;
        font-size: 1.2rem;
        font-weight: 600;
        margin-bottom: 15px;
    }
    
    /* Modern Glassmorphic Container Cards */
    .glass-card {
        background: rgba(17, 24, 39, 0.65);
        border: 1px solid rgba(255, 255, 255, 0.05);
        border-radius: 16px;
        padding: 24px;
        backdrop-filter: blur(12px);
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.4);
        margin-bottom: 20px;
    }
    
    /* Dynamic Threat Status Banners */
    .status-banner {
        padding: 16px;
        border-radius: 12px;
        font-weight: 700;
        font-size: 1.1rem;
        letter-spacing: 0.03em;
        text-align: center;
        margin-bottom: 20px;
        text-transform: uppercase;
    }
    
    .status-danger {
        background: rgba(255, 75, 75, 0.12);
        color: #FF4B4B;
        border: 1px solid rgba(255, 75, 75, 0.3);
        box-shadow: 0 0 15px rgba(255, 75, 75, 0.05);
    }
    
    .status-safe {
        background: rgba(0, 230, 118, 0.12);
        color: #00E676;
        border: 1px solid rgba(0, 230, 118, 0.3);
        box-shadow: 0 0 15px rgba(0, 230, 118, 0.05);
    }
    
    /* Interactive Threat Pill Badges */
    .pill-badge {
        display: inline-block;
        background: rgba(255, 75, 75, 0.12);
        color: #FF4B4B;
        border: 1px solid rgba(255, 75, 75, 0.25);
        padding: 6px 14px;
        border-radius: 30px;
        margin: 5px;
        font-size: 0.82rem;
        font-weight: 600;
        letter-spacing: 0.02em;
    }
</style>
""", unsafe_allow_html=True)

# =====================================
# CACHED RESOURCE LOADING
# =====================================
@st.cache_resource
def load_ml_pipeline():
    try:
        model = joblib.load("models/phishing_model.pkl")
        vectorizer = joblib.load("models/tfidf_vectorizer.pkl")
        return model, vectorizer
    except Exception:
        return None, None

email_model, vectorizer = load_ml_pipeline()

# =====================================
# ENGINE PIPELINES & DATA CORE
# =====================================
def clean_text(text):
    text = str(text).lower()
    text = re.sub(r"http\S+", "", text)
    text = re.sub(r"[^a-zA-Z\s]", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text

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

    if "-" in url:
        score += 15
        reasons.append("HYPHEN_OBFUSCATION")

    if not url.lower().startswith("https://"):
        score += 20
        reasons.append("MISSING_HTTPS")

    suspicious_words = ["login", "verify", "secure", "update", "account", "bank", "paypal"]
    for word in suspicious_words:
        if word in url.lower():
            score += 10
            reasons.append(f"KEYWORD_{word.upper()}")

    return min(score, 100), reasons
# =====================================
# SIDEBAR NAVIGATION MATRIX
# =====================================
with st.sidebar:
    st.write("")
    st.markdown('<p style="color: #6C7A9C; text-transform: uppercase; font-size: 0.75rem; font-weight: 700; letter-spacing: 0.1em; margin-bottom: 15px;">🛡️ SecOps Navigation</p>', unsafe_allow_html=True)
    app_mode = st.radio(
    "Navigate Workspaces",
    [
        "🛡️ SOC Overview",
        "📧 Email Security Analyzer",
        "🌐 Domain Integrity Scanner",
        "🚨 SOC Alert Queue",
        "🔎 Incident Investigation",
        "📄 Reports"
    ],
        label_visibility="collapsed"
    )
    st.write("")
    st.markdown("---")
    st.markdown(f"<p style='color: #6C7A9C; font-size: 0.85rem;'>Runtime Scan Records: <strong style='color: #00F0FF;'>{len(runtime_workspace['scan_history'])}</strong></p>", unsafe_allow_html=True)

# =====================================
# PLATFORM BRAND HEADER
# =====================================
st.markdown('<h1 class="main-title">🛡️ AI CyberShield</h1>', unsafe_allow_html=True)
st.markdown('<p class="sub-title">Unified SecOps Intelligence Platform for Real-Time Threat Assessment</p>', unsafe_allow_html=True)
st.markdown(f"<h3 style='color: #E2E8F0; font-weight: 500; margin-bottom: 20px;'>{app_mode.split(' ', 1)[1]}</h3>", unsafe_allow_html=True)

# =====================================
# PAGE 1: EMAIL DETECTOR ARCHITECTURE
# =====================================
if app_mode == "📧 Email Security Analyzer":

    # Restore the last analyzed payload after a browser refresh/new Streamlit session.
    if (
        "email_input_area" not in st.session_state
        and runtime_workspace["email_result"] is not None
    ):
        st.session_state["email_input_area"] = runtime_workspace["email_result"]["input"]

    header_left, header_right = st.columns([4, 1])

    with header_left:
        st.markdown(
            '<div class="panel-header">📥 Email Analysis Workspace</div>',
            unsafe_allow_html=True
        )
        st.caption(
            "Your latest email analysis stays here while the app is running. "
            "Use New Analysis only when you want to clear it."
        )

    with header_right:
        if st.button(
            "↻ New Analysis",
            use_container_width=True,
            key="clear_email_workspace"
        ):
            runtime_workspace["email_result"] = None
            st.session_state.pop("email_input_area", None)
            st.rerun()

    email_text = st.text_area(
        "Paste Email Content Here",
        height=220,
        placeholder="Paste suspicious or unverified email content here...",
        key="email_input_area",
        label_visibility="collapsed"
    )

    analyze_email_btn = st.button(
        "🚀 Analyze Email Signature",
        use_container_width=True,
        type="primary"
    )

    if analyze_email_btn:
        if not email_text.strip():
            st.warning("⚠️ Target buffer empty. Please provide text payload to evaluate.")
        elif email_model is None:
            st.error("ML Assets are missing inside the 'models/' route directory.")
        else:
            cleaned = clean_text(email_text)
            vector = vectorizer.transform([cleaned])
            prediction = email_model.predict(vector)[0]
            probability = email_model.predict_proba(vector)[0]
            confidence = round(max(probability) * 100, 2)
            prediction_label = "Phishing" if prediction == 1 else "Legitimate"

            suspicious_words = [
                "urgent", "verify", "password", "bank", "account",
                "click", "login", "suspended", "payment", "security"
            ]
            matched_words = [word for word in suspicious_words if word in cleaned]

            iocs = extract_iocs(email_text)
            ioc_labels = [
                f"{key}: {len(values)}"
                for key, values in iocs.items()
                if values
            ]

            if prediction == 1:
                risk_status = "CRITICAL"
                bar_val = int(confidence)
                verdict = "CRITICAL THREAT"
                accent_color = "#FF4B4B"
                banner_type = "danger"

                add_security_alert(
                    source="Email Analyzer",
                    threat_type="Credential Phishing",
                    confidence=confidence,
                    risk_score=int(confidence),
                    indicators=matched_words + ioc_labels,
                    summary="ML phishing detection triggered a SOC alert."
                )
            else:
                risk_status = "NEGLIGIBLE"
                bar_val = 100 - int(confidence)
                verdict = "SAFE"
                accent_color = "#00E676"
                banner_type = "safe"

            add_history_record(
                "Email Payload",
                email_text,
                f"{confidence}%",
                verdict
            )

            with st.spinner("🤖 AI is analyzing the threat signature..."):
                analysis = generate_threat_analysis(
                    email_text=email_text,
                    prediction=prediction_label
                )

                incident_report = generate_incident_report(
                    analysis=analysis,
                    analysis_type="Email Analysis",
                    threat_level=prediction_label,
                    threat_type=prediction_label,
                    risk_score=f"{confidence}%"
                )

            runtime_workspace["email_result"] = {
                "input": email_text,
                "prediction": prediction_label,
                "confidence": confidence,
                "risk_status": risk_status,
                "bar_val": bar_val,
                "verdict": verdict,
                "accent_color": accent_color,
                "banner_type": banner_type,
                "matched_words": matched_words,
                "iocs": iocs,
                "ioc_labels": ioc_labels,
                "analysis": analysis,
                "incident_report": incident_report,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            runtime_workspace["latest_incident_report"] = incident_report

    email_result = runtime_workspace["email_result"]

    if email_result is not None:
        st.markdown("---")
        st.markdown(
            '<div class="panel-header">📊 Analysis Result</div>',
            unsafe_allow_html=True
        )
        st.caption(f"Last analyzed: {email_result['timestamp']}")

        if email_result["banner_type"] == "danger":
            st.markdown(
                '<div class="status-banner status-danger">'
                '🚨 Threat Detected: Phishing Vector Flagged</div>',
                unsafe_allow_html=True
            )
        else:
            st.markdown(
                '<div class="status-banner status-safe">'
                '✅ Clean Signature: Legitimate Match</div>',
                unsafe_allow_html=True
            )

        m1, m2, m3 = st.columns([1, 1, 2])
        m1.metric("Calculated Vector", email_result["risk_status"])
        m2.metric("Pipeline Confidence", f'{email_result["confidence"]}%')
        with m3:
            st.write("**Threat Intensity Metric**")
            st.progress(int(email_result["bar_val"]))

        indicators = email_result["matched_words"] + email_result["ioc_labels"]
        if indicators:
            st.markdown(
                '<p style="color:#E2E8F0;font-size:1rem;font-weight:600;'
                'margin-top:15px;margin-bottom:10px;">🔍 Security Indicators</p>',
                unsafe_allow_html=True
            )
            pills_layout = "".join(
                [
                    f'<span class="pill-badge">📌 {indicator.upper()}</span>'
                    for indicator in indicators
                ]
            )
            st.markdown(
                f'<div class="glass-card" style="padding:15px;">'
                f'{pills_layout}</div>',
                unsafe_allow_html=True
            )

        st.markdown(
            '<div class="panel-header" style="margin-top:15px;">'
            '🤖 Deep Intel: AI Threat Analysis</div>',
            unsafe_allow_html=True
        )
        st.markdown(
            f'<div class="glass-card" style="border-left:4px solid '
            f'{email_result["accent_color"]};">',
            unsafe_allow_html=True
        )
        st.markdown(email_result["analysis"])
        st.markdown("</div>", unsafe_allow_html=True)

    else:
        st.markdown("""
            <div class="glass-card" style="text-align:center;padding:60px 10px;
            color:#6C7A9C;border:1px dashed rgba(255,255,255,0.05)">
                <span style="font-size:2.5rem;">📧</span>
                <p style="margin-top:15px;font-size:0.95rem;font-weight:500;
                color:#94A3B8;">No active email analysis</p>
                <p style="font-size:0.85rem;color:#475569;">
                Paste an email above and run the analyzer. The result will remain
                available until you start a new analysis.</p>
            </div>
        """, unsafe_allow_html=True)


# =====================================
# PAGE 2: WEBSITE DETECTOR ARCHITECTURE
# =====================================
elif app_mode == "🌐 Domain Integrity Scanner":

    if (
        "url_input_field" not in st.session_state
        and runtime_workspace["website_result"] is not None
    ):
        st.session_state["url_input_field"] = runtime_workspace["website_result"]["input"]

    header_left, header_right = st.columns([4, 1])

    with header_left:
        st.markdown(
            '<div class="panel-header">🌐 Domain Analysis Workspace</div>',
            unsafe_allow_html=True
        )
        st.caption(
            "Your latest website analysis stays here while the app is running. "
            "Use New Analysis only when you want to clear it."
        )

    with header_right:
        if st.button(
            "↻ New Analysis",
            use_container_width=True,
            key="clear_website_workspace"
        ):
            runtime_workspace["website_result"] = None
            st.session_state.pop("url_input_field", None)
            st.rerun()

    url_input = st.text_input(
        "Enter Website URL to Evaluate",
        placeholder="example: https://secure-login-verification-portal.com",
        key="url_input_field",
        label_visibility="collapsed"
    )

    analyze_url_btn = st.button(
        "🌐 Execute Heuristic Domain Scan",
        use_container_width=True,
        type="primary"
    )

    if analyze_url_btn:
        if not url_input.strip():
            st.warning("⚠️ Please provide a valid URL string.")
        else:
            score, reasons = analyze_url(url_input)
            verdict = "High Risk" if score >= 50 else "Low Risk"

            if score >= 50:
                accent_color = "#FF4B4B"
                banner_type = "danger"
                history_verdict = "HIGH RISK"

                add_security_alert(
                    source="Domain Integrity Scanner",
                    threat_type="Phishing Website",
                    confidence=score,
                    risk_score=int(score),
                    indicators=reasons,
                    summary=(
                        "Heuristic URL analysis identified a potentially "
                        "malicious website."
                    )
                )
            else:
                accent_color = "#00E676"
                banner_type = "safe"
                history_verdict = "LOW RISK"

            add_history_record(
                "URL Target",
                url_input,
                f"{score}/100",
                history_verdict
            )

            with st.spinner("🤖 AI is analyzing the website..."):
                website_analysis = generate_website_analysis(
                    url=url_input,
                    risk_score=score,
                    indicators=reasons,
                    verdict=verdict
                )

                incident_report = generate_incident_report(
                    analysis=website_analysis,
                    analysis_type="Website Analysis",
                    threat_level=verdict,
                    threat_type="Website Threat Analysis",
                    risk_score=f"{score}/100"
                )

            runtime_workspace["website_result"] = {
                "input": url_input,
                "score": score,
                "reasons": reasons,
                "verdict": verdict,
                "accent_color": accent_color,
                "banner_type": banner_type,
                "analysis": website_analysis,
                "incident_report": incident_report,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            runtime_workspace["latest_incident_report"] = incident_report

    website_result = runtime_workspace["website_result"]

    if website_result is not None:
        st.markdown("---")
        st.markdown(
            '<div class="panel-header">📊 Analysis Result</div>',
            unsafe_allow_html=True
        )
        st.caption(f"Last analyzed: {website_result['timestamp']}")

        if website_result["banner_type"] == "danger":
            st.markdown(
                '<div class="status-banner status-danger">'
                '⚠️ Threat Warning: High-Risk Phishing URL Profile</div>',
                unsafe_allow_html=True
            )
        else:
            st.markdown(
                '<div class="status-banner status-safe">'
                '✅ Clean Verification: Low Profile Risks</div>',
                unsafe_allow_html=True
            )

        m1, m2, m3 = st.columns(3)
        m1.metric("Domain Risk Score", f'{website_result["score"]}/100')
        m2.metric("Assessment", website_result["verdict"])
        m3.metric("Indicators", len(website_result["reasons"]))

        st.write("**Heuristic Risk Density**")
        st.progress(int(website_result["score"]))

        if website_result["reasons"]:
            pills_layout = "".join(
                [
                    f'<span class="pill-badge">📌 {reason.upper()}</span>'
                    for reason in website_result["reasons"]
                ]
            )
            st.markdown(
                f'<div class="glass-card" style="padding:15px;">'
                f'{pills_layout}</div>',
                unsafe_allow_html=True
            )

        st.markdown(
            '<div class="panel-header" style="margin-top:15px;">'
            '🤖 Deep Intel: AI Website Threat Analysis</div>',
            unsafe_allow_html=True
        )
        st.markdown(
            f'<div class="glass-card" style="border-left:4px solid '
            f'{website_result["accent_color"]};">',
            unsafe_allow_html=True
        )
        st.markdown(website_result["analysis"])
        st.markdown("</div>", unsafe_allow_html=True)

    else:
        st.markdown("""
            <div class="glass-card" style="text-align:center;padding:60px 10px;
            color:#6C7A9C;border:1px dashed rgba(255,255,255,0.05)">
                <span style="font-size:2.5rem;">🌐</span>
                <p style="margin-top:15px;font-size:0.95rem;font-weight:500;
                color:#94A3B8;">No active domain analysis</p>
                <p style="font-size:0.85rem;color:#475569;">
                Enter a URL above and run the scanner. The result will remain
                available until you start a new analysis.</p>
            </div>
        """, unsafe_allow_html=True)

# =====================================
# PAGE 3: SOC OVERVIEW
# =====================================
elif app_mode == "🛡️ SOC Overview":
    st.markdown("## 🛡️ SOC Overview")
    alerts = get_all_alerts()

    if alerts:
        df = pd.DataFrame(alerts)
        total = len(df)
        critical = int((df["severity"] == "CRITICAL").sum())
        high = int((df["severity"] == "HIGH").sum())
        open_alerts = int((df["status"] == "OPEN").sum())

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Alerts", total)
        m2.metric("Critical", critical)
        m3.metric("High", high)
        m4.metric("Open Investigations", open_alerts)

        st.write("")
        left, right = st.columns(2, gap="large")

        with left:
            st.markdown('<div class="panel-header">📊 Alert Severity Distribution</div>', unsafe_allow_html=True)
            severity_df = (df["severity"].value_counts().reindex(["CRITICAL","HIGH","MEDIUM","LOW"], fill_value=0).rename_axis("Severity").reset_index(name="Alerts"))
            st.bar_chart(severity_df, x="Severity", y="Alerts", use_container_width=True)

        with right:
            st.markdown('<div class="panel-header">🚦 Investigation Status</div>', unsafe_allow_html=True)
            status_df = (df["status"].value_counts().reindex(["OPEN","INVESTIGATING","CONTAINED","RESOLVED","CLOSED"], fill_value=0).rename_axis("Status").reset_index(name="Alerts"))
            st.bar_chart(status_df, x="Status", y="Alerts", use_container_width=True)

        st.markdown('<div class="panel-header">🎯 Threat Type Distribution</div>', unsafe_allow_html=True)
        threat_df = df["threat_type"].value_counts().rename_axis("Threat Type").reset_index(name="Alerts")
        st.bar_chart(threat_df, x="Threat Type", y="Alerts", use_container_width=True)

        st.markdown("---")
        st.markdown('<div class="panel-header">🕒 Recent Security Alerts</div>', unsafe_allow_html=True)
        recent = ["alert_id","timestamp","source","threat_type","severity","priority","risk_score","status"]
        st.dataframe(df[recent].head(10), use_container_width=True, hide_index=True)
        st.caption("Overview data is loaded from the persistent SQLite alert database.")
    else:
        st.info("No SOC alerts yet. Run an email or URL analysis to populate the dashboard.")

# =====================================
# PAGE 4: SOC ALERT QUEUE
# =====================================

elif app_mode == "🚨 SOC Alert Queue":

    st.markdown("## 🚨 SOC Alert Queue")

    # Load persistent alerts from SQLite
    alerts = get_all_alerts()

    if alerts:

        df = pd.DataFrame(alerts)

        # -------------------------------------
        # ALERT FILTERS
        # -------------------------------------

        st.markdown("### 🔎 Alert Filters")

        f1, f2, f3, f4 = st.columns(4)

        with f1:
            search_id = st.text_input(
                "Search Alert ID",
                placeholder="CS-2026..."
            )

        with f2:
            severity_options = [
                "ALL",
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW"
            ]

            severity_filter = st.selectbox(
                "Severity",
                severity_options
            )

        with f3:
            status_options = [
                "ALL",
                "OPEN",
                "INVESTIGATING",
                "CONTAINED",
                "RESOLVED",
                "CLOSED"
            ]

            status_filter = st.selectbox(
                "Status",
                status_options
            )

        with f4:
            threat_options = [
                "ALL"
            ] + sorted(
                df["threat_type"].dropna().unique().tolist()
            )

            threat_filter = st.selectbox(
                "Threat Type",
                threat_options
            )

        # -------------------------------------
        # APPLY FILTERS
        # -------------------------------------

        filtered_df = df.copy()

        if search_id.strip():
            filtered_df = filtered_df[
                filtered_df["alert_id"]
                .str.contains(
                    search_id.strip(),
                    case=False,
                    na=False
                )
            ]

        if severity_filter != "ALL":
            filtered_df = filtered_df[
                filtered_df["severity"] == severity_filter
            ]

        if status_filter != "ALL":
            filtered_df = filtered_df[
                filtered_df["status"] == status_filter
            ]

        if threat_filter != "ALL":
            filtered_df = filtered_df[
                filtered_df["threat_type"] == threat_filter
            ]

        # -------------------------------------
        # METRICS
        # -------------------------------------

        st.write("")

        a, b, c, d = st.columns(4)

        a.metric(
            "Total Alerts",
            len(filtered_df)
        )

        b.metric(
            "Critical",
            int(
                (filtered_df["severity"] == "CRITICAL")
                .sum()
            )
        )

        c.metric(
            "High",
            int(
                (filtered_df["severity"] == "HIGH")
                .sum()
            )
        )

        d.metric(
            "Open",
            int(
                (filtered_df["status"] == "OPEN")
                .sum()
            )
        )

        st.write("")

        # -------------------------------------
        # ALERT TABLE
        # -------------------------------------

        columns = [
            "alert_id",
            "timestamp",
            "source",
            "threat_type",
            "severity",
            "priority",
            "confidence",
            "risk_score",
            "status"
        ]

        if not filtered_df.empty:

            st.dataframe(
                filtered_df[columns],
                use_container_width=True,
                hide_index=True
            )

        else:

            st.info(
                "No alerts match the selected filters."
            )

        # -------------------------------------
        # DELETE INDIVIDUAL ALERT
        # -------------------------------------

        st.markdown("---")

        st.markdown("### 🗑️ Alert Management")

        alert_ids = df["alert_id"].tolist()

        selected_delete = st.selectbox(
            "Select Alert to Delete",
            ["NONE"] + alert_ids,
            key="delete_alert_selection"
        )

        if selected_delete != "NONE":

            selected_alert = get_alert(selected_delete)

            if selected_alert:

                st.warning(
                    f"You are about to permanently delete "
                    f"**{selected_delete}** "
                    f"({selected_alert['threat_type']})."
                )

                if st.button(
                    "🗑️ Delete Selected Alert",
                    type="secondary",
                    key="delete_selected_alert"
                ):

                    delete_alert(selected_delete)

                    st.success(
                        f"Alert {selected_delete} deleted."
                    )

                    st.rerun()

        # -------------------------------------
        # RETENTION / CLEANUP
        # -------------------------------------

        st.markdown("### 🧹 Closed Alert Cleanup")

        st.write(
            "Remove CLOSED alerts older than the selected "
            "retention period. Open and active investigations "
            "will not be removed."
        )

        retention_days = st.selectbox(
            "Keep closed alerts for",
            [7, 30, 60, 90],
            index=1,
            format_func=lambda x: f"{x} days",
            key="retention_days"
        )

        if st.button(
            "🧹 Delete Expired Closed Alerts",
            key="delete_old_alerts"
        ):

            deleted_count = delete_old_closed_alerts(
                retention_days
            )

            if deleted_count > 0:

                st.success(
                    f"{deleted_count} expired closed alert(s) "
                    f"were removed."
                )

                st.rerun()

            else:

                st.info(
                    "No closed alerts have exceeded the "
                    "selected retention period."
                )

    else:

        st.info(
            "No SOC alerts yet. Run an email or URL analysis first."
        )

        # =====================================
# PAGE 5: INCIDENT INVESTIGATION
# =====================================

elif app_mode == "🔎 Incident Investigation":

    st.markdown("## 🔎 Incident Investigation")

    # Load alerts from persistent SQLite database
    alerts = get_all_alerts()

    # -------------------------------------
    # EMPTY STATE
    # -------------------------------------

    if not alerts:

        st.info(
            "No security incidents available for investigation. "
            "Run a phishing email or high-risk website analysis first."
        )

    else:

        # -------------------------------------
        # INCIDENT SELECTION
        # -------------------------------------

        choices = {
            alert["alert_id"]: alert
            for alert in alerts
        }

        selected = st.selectbox(
            "Select Incident",
            list(choices.keys()),
            format_func=lambda alert_id: (
                f"{alert_id} | "
                f"{choices[alert_id]['severity']} | "
                f"{choices[alert_id]['threat_type']}"
            )
        )

        # Get selected incident
        incident = get_alert(selected)

        if incident is None:

            st.error("Unable to load the selected incident.")

        else:

            # -------------------------------------
            # INCIDENT OVERVIEW
            # -------------------------------------

            st.markdown("### Incident Overview")

            a, b, c, d = st.columns(4)

            a.metric(
                "Severity",
                incident["severity"]
            )

            b.metric(
                "Priority",
                incident["priority"]
            )

            c.metric(
                "Risk Score",
                f"{incident['risk_score']}/100"
            )

            d.metric(
                "Confidence",
                f"{incident['confidence']}%"
            )

            st.markdown("---")

            # -------------------------------------
            # INCIDENT DETAILS
            # -------------------------------------

            st.markdown("### Incident Details")

            col1, col2 = st.columns(2)

            with col1:

                st.write(
                    "**Alert ID:**",
                    incident["alert_id"]
                )

                st.write(
                    "**Source:**",
                    incident["source"]
                )

                st.write(
                    "**Threat Type:**",
                    incident["threat_type"]
                )

            with col2:

                st.write(
                    "**Timestamp:**",
                    incident["timestamp"]
                )

                st.write(
                    "**Current Status:**",
                    incident["status"]
                )

                st.write(
                    "**Risk Score:**",
                    f"{incident['risk_score']}/100"
                )

            st.write(
                "**Summary:**",
                incident["summary"]
            )

            # -------------------------------------
            # INDICATORS OF COMPROMISE
            # -------------------------------------

            st.markdown("### 🔍 Indicators of Compromise")

            indicators = incident.get("indicators", [])

            if indicators:

                for indicator in indicators:

                    st.markdown(
                        f"- `{indicator}`"
                    )

            else:

                st.info(
                    "No indicators of compromise were recorded."
                )

            # -------------------------------------
            # MITRE ATT&CK MAPPING
            # -------------------------------------

            st.markdown("### 🛡️ MITRE ATT&CK Mapping")

            mitre_data = incident.get(
                "mitre_techniques",
                []
            )

            if mitre_data:

                mitre_df = pd.DataFrame(
                    mitre_data
                )

                st.dataframe(
                    mitre_df,
                    use_container_width=True,
                    hide_index=True
                )

            else:

                st.info(
                    "No MITRE ATT&CK technique mapped."
                )

            st.markdown("---")

            # -------------------------------------
            # INCIDENT STATUS MANAGEMENT
            # -------------------------------------

            st.markdown("### 🚦 Incident Status")

            statuses = [
                "OPEN",
                "INVESTIGATING",
                "CONTAINED",
                "RESOLVED",
                "CLOSED"
            ]

            current_status = incident.get(
                "status",
                "OPEN"
            )

            new_status = st.selectbox(
                "Update Incident Status",
                statuses,
                index=(
                    statuses.index(current_status)
                    if current_status in statuses
                    else 0
                ),
                key=f"status_{selected}"
            )

            if st.button(
                "💾 Update Status",
                type="primary",
                key=f"update_status_{selected}"
            ):

                update_alert_status(
                    selected,
                    new_status
                )

                st.success(
                    f"{selected} updated to {new_status}."
                )

                st.rerun()
                
# =====================================
# PAGE 6: REPORTS
# =====================================
elif app_mode == "📄 Reports":
    st.markdown("## 📄 Security Reports")
    alerts = get_all_alerts()

    if alerts:
        report_df = pd.DataFrame(alerts)
        columns = ["alert_id","timestamp","source","threat_type","severity","priority","confidence","risk_score","status","summary"]
        csv_report = report_df[columns].to_csv(index=False).encode("utf-8")
        st.download_button("📥 Download SOC Alert Report (CSV)", csv_report, file_name=f"cybershield_soc_alerts_{datetime.now().strftime('%Y%m%d%H%M')}.csv", mime="text/csv", use_container_width=True)

        if runtime_workspace["latest_incident_report"] is not None:
            st.markdown("---")
            st.markdown('<div class="panel-header">📄 Latest AI Incident Report</div>', unsafe_allow_html=True)
            st.markdown('<div class="glass-card">', unsafe_allow_html=True)
            st.markdown(runtime_workspace["latest_incident_report"])
            st.markdown('</div>', unsafe_allow_html=True)
            pdf_path = create_incident_pdf(runtime_workspace["latest_incident_report"])
            with open(pdf_path, "rb") as pdf_file:
                st.download_button("📄 Download AI Incident Report (PDF)", pdf_file, file_name="AI_CyberShield_Incident_Report.pdf", mime="application/pdf", use_container_width=True)
        else:
            st.info("No AI incident report is available in the current session yet.")
    else:
        st.info("No security alerts available for reporting. Run an email or URL analysis first.")

# FOOTER CREDITS METADATA
# =====================================
st.markdown('<hr style="border-color: rgba(255,255,255,0.05); margin-top: 30px; margin-bottom: 15px;" />', unsafe_allow_html=True)
f_left, f_right = st.columns(2)
with f_left:
    st.markdown("<p style='color:#475569; font-size:0.8rem; margin:0;'>AI CyberShield Framework • Platform Node Active • Partitioned State Workspaces</p>", unsafe_allow_html=True)
with f_right:
    st.markdown("<p style='text-align:right; color:#475569; font-size:0.8rem; margin:0;'>Built by Zainab Imdad</p>", unsafe_allow_html=True)