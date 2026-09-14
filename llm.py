from dotenv import load_dotenv
import os
import time
from datetime import datetime
import uuid

import streamlit as st

load_dotenv()

# ============================================================
# GOOGLE GEMINI CONFIGURATION
# ============================================================

try:
    from google import genai
    from google.genai import types
except ImportError:
    genai = None
    types = None


MODEL_NAME = "gemini-3.6-flash"


# ------------------------------------------------------------
# API KEY
# ------------------------------------------------------------
# Local:
#   .env -> GOOGLE_API_KEY
#
# Streamlit Cloud:
#   Settings -> Secrets
#   GOOGLE_API_KEY = "..."
# ------------------------------------------------------------

_api_key = os.getenv("GOOGLE_API_KEY")

if not _api_key:
    try:
        _api_key = st.secrets["GOOGLE_API_KEY"]
    except Exception:
        _api_key = None


_client = (
    genai.Client(api_key=_api_key)
    if (genai and _api_key)
    else None
)


# ============================================================
# GEMINI GENERATION ENGINE
# ============================================================

def _generate(prompt: str) -> str:
    """
    Send a prompt to Gemini with automatic retry handling
    for temporary service availability errors.
    """

    if _client is None:

        if not genai:
            raise RuntimeError(
                "google-genai is not installed. "
                "Run: pip install google-genai"
            )

        raise RuntimeError(
            "GOOGLE_API_KEY is not configured."
        )

    config = (
        types.GenerateContentConfig(
            temperature=0.3
        )
        if types
        else None
    )

    last_error = None

    # Three attempts for temporary Gemini failures
    for attempt in range(3):

        try:

            response = _client.models.generate_content(
                model=MODEL_NAME,
                contents=prompt,
                config=config,
            )

            text = getattr(response, "text", None)

            if not text:
                raise RuntimeError(
                    "Gemini returned an empty response."
                )

            return text

        except Exception as e:

            last_error = e

            error_text = str(e).upper()

            # Retry temporary availability errors
            if (
                "503" in error_text
                or "UNAVAILABLE" in error_text
            ):

                # 1 second -> 2 seconds -> 4 seconds
                time.sleep(2 ** attempt)

                continue

            # Do not retry permanent errors
            raise

    raise RuntimeError(
        f"Gemini temporarily unavailable after 3 attempts: "
        f"{last_error}"
    )


# ============================================================
# EMAIL SECURITY PROMPT
# ============================================================

email_security_prompt = """
You are a senior SOC email security analyst.

You are reviewing a pasted email. A machine-learning classifier has also produced a preliminary verdict,
but that verdict is NOT ground truth. Your job is to independently assess the supplied message and explain
whether the evidence supports a phishing/suspicious or legitimate assessment.

ML preliminary verdict:
{prediction}

Sender:
{sender}

Subject:
{subject}

Contains links:
{has_links}

Attachment references:
{has_attachments}

Email content:
{email}

Use ONLY the evidence supplied above. Do not invent sender authentication results, domain reputation,
malware, attachments, spoofing, or user activity that is not present.

Return concise SOC-style Markdown with exactly these sections:

## Analyst verdict

Choose: Suspicious / Likely legitimate / Inconclusive

## Key indicators

List only indicators visible in the supplied message or metadata.

If none are present, say:

No clear security indicators identified from the supplied content.

## Reasoning

Explain briefly why the evidence supports the analyst verdict.

Treat the ML result as a separate signal.

## Recommended action

Give 2–4 practical next steps appropriate to the evidence.

Important:

- A legitimate ML result does not force a legitimate AI assessment.
- A phishing ML result does not prove phishing by itself.
- Do not claim certainty when the supplied evidence is insufficient.
"""


# ============================================================
# EMAIL THREAT ANALYSIS
# ============================================================

def generate_threat_analysis(
    email_text: str,
    prediction: str,
    sender: str = "Unknown",
    subject: str = "Unknown",
    has_links: str = "Unknown",
    has_attachments: str = "Unknown",
) -> str:
    """
    Generate AI-assisted email security analysis.
    """

    try:

        prompt = email_security_prompt.format(
            prediction=prediction,
            sender=sender,
            subject=subject,
            has_links=has_links,
            has_attachments=has_attachments,
            email=email_text,
        )

        return _generate(prompt)

    except Exception as e:

        error_text = str(e).upper()

        # Temporary Gemini service outage
        if (
            "503" in error_text
            or "UNAVAILABLE" in error_text
        ):

            return """
## 🤖 AI Analysis Temporarily Unavailable

The Gemini AI analysis service is temporarily experiencing
high demand.

### Detection Result

The underlying machine-learning detection result remains
available and should be used as the primary detection signal.

### Analyst Action

Review the email evidence, risk score, confidence, and
detected indicators while AI enrichment is temporarily
unavailable.

**Detection Status:** Available

**AI Status:** Temporarily unavailable

Please retry the AI analysis later.
"""

        # API key / configuration problem
        if (
            "API_KEY" in error_text
            or "API KEY" in error_text
            or "NOT CONFIGURED" in error_text
        ):

            return """
## ⚠️ AI Analysis Configuration Error

The Gemini AI analysis engine could not access a valid API key.

### Detection Result

The underlying machine-learning detection remains available.

**Detection Status:** Available

**AI Status:** Configuration error

Please verify the Gemini API key configuration.
"""

        # Other errors
        return f"""
## 🤖 AI Analysis Unavailable

The AI enrichment service could not complete the analysis.

### Detection Result

The underlying security detection remains available.

**Detection Status:** Available

**AI Status:** Unavailable

Please retry the AI analysis later.

**Technical Details:** {str(e)}
"""


# ============================================================
# WEBSITE / DOMAIN SECURITY ANALYSIS
# ============================================================

def generate_website_analysis(
    url,
    risk_score,
    indicators,
    verdict,
):
    """
    Generate AI-assisted website security analysis.
    """

    website_prompt = """
You are an expert Cybersecurity Web Security Analyst.

A heuristic phishing detection engine has already analyzed a website.

Website URL:
{url}

Risk Score:
{risk_score}/100

Verdict:
{verdict}

Detected Indicators:
{indicators}

Your task is to generate a professional cybersecurity assessment based ONLY on the information provided.

Never invent facts.
Never speculate about hypothetical situations.
Do not assume indicators that are not provided.
Base every conclusion only on the supplied URL, heuristic score and detected indicators.

----------------------------------------
IF Verdict = HIGH RISK
----------------------------------------

Generate the report using this format exactly:

# 🌐 AI Website Threat Analysis

## Threat Level

(High)

## Website Assessment

Briefly explain why the website is considered suspicious.

## Detected Security Indicators

Explain each detected indicator in simple language.

## URL Structure Analysis

Discuss only the characteristics actually detected, such as:

- HTTPS usage
- Domain structure
- Suspicious keywords
- Hyphens
- URL length
- Subdomains
- Brand impersonation

Do not mention indicators that are not present.

## Potential Risks

Explain realistic risks such as:

- Credential theft
- Fake login pages
- Malware delivery
- Financial fraud

Only include risks supported by the detected indicators.

## Recommended Actions

Provide 5 practical security recommendations.

## Executive Summary

Summarize the overall assessment in 2–3 concise sentences.

----------------------------------------
IF Verdict = LOW RISK
----------------------------------------

Generate the report using this format exactly:

# 🌐 AI Website Security Assessment

## Security Status

(Low Risk)

## Website Assessment

Explain why the website appears safe based on the heuristic analysis.

## Positive Security Indicators

List only the positive indicators actually observed.

Examples include:

- HTTPS enabled
- Clean domain structure
- No suspicious keywords
- Normal URL length
- No excessive subdomains

Only mention those that are actually supported by the heuristic analysis.

## Good Security Practices

Provide 3–5 general cybersecurity tips for safely browsing legitimate websites.

## Executive Summary

Summarize why the website currently appears safe.

----------------------------------------
Important Rules
----------------------------------------

- Never generate hypothetical attack scenarios.
- Never mention malware, credential theft or phishing risks for LOW RISK websites.
- Never include sections that do not belong to the selected report type.
- Keep the response concise, professional and suitable for a cybersecurity dashboard.
"""

    try:

        prompt = website_prompt.format(
            url=url,
            risk_score=risk_score,
            verdict=verdict,
            indicators=(
                ", ".join(indicators)
                if indicators
                else "None"
            ),
        )

        return _generate(prompt)

    except Exception as e:

        error_text = str(e).upper()

        # Temporary Gemini service outage
        if (
            "503" in error_text
            or "UNAVAILABLE" in error_text
        ):

            return """
## 🤖 AI Analysis Temporarily Unavailable

The Gemini AI analysis service is temporarily experiencing
high demand.

### Detection Result

The underlying website security detection remains available
and is based on the URL analysis engine and detected
security indicators.

### Analyst Action

Review the URL, risk score, verdict, and detected indicators
while AI enrichment is temporarily unavailable.

**Detection Status:** Available

**AI Status:** Temporarily unavailable

Please retry the AI analysis later.
"""

        # API key / configuration problem
        if (
            "API_KEY" in error_text
            or "API KEY" in error_text
            or "NOT CONFIGURED" in error_text
        ):

            return """
## ⚠️ AI Analysis Configuration Error

The Gemini AI analysis engine could not access a valid API key.

### Detection Result

The underlying website security detection remains available.

**Detection Status:** Available

**AI Status:** Configuration error

Please verify the Gemini API key configuration.
"""

        # Other errors
        return f"""
## 🤖 AI Analysis Unavailable

The AI enrichment service could not complete the analysis.

### Detection Result

The underlying website security assessment remains available.

**Detection Status:** Available

**AI Status:** Unavailable

Please retry the AI analysis later.

**Technical Details:** {str(e)}
"""


# ============================================================
# INCIDENT REPORT PROMPT
# ============================================================

incident_report_prompt = """
You are a Senior SOC (Security Operations Center) Incident Response Analyst.

Generate a professional cybersecurity incident report.

Incident ID:
{incident_id}

Generated On:
{generated_time}

Analysis Type:
{analysis_type}

Threat Level:
{threat_level}

Threat Classification:
{threat_type}

Risk Score:
{risk_score}

AI Analysis:
{analysis}

Generate the report in the following professional format.

══════════════════════════════════════════════════════════════
               AI CYBERSHIELD INCIDENT REPORT
══════════════════════════════════════════════════════════════

Incident ID      : {incident_id}

Generated On     : {generated_time}

Generated By     : AI CyberShield Intelligence Engine

Analysis Type    : {analysis_type}

Threat Level     : {threat_level}

Threat Status    : ACTIVE

══════════════════════════════════════════════════════════════
EXECUTIVE SUMMARY
══════════════════════════════════════════════════════════════

Write a concise executive summary (3–5 lines) explaining the incident.

══════════════════════════════════════════════════════════════
TECHNICAL ANALYSIS
══════════════════════════════════════════════════════════════

Threat Classification
---------------------

{threat_type}

Detailed Findings
-----------------

Summarize the important technical findings from the AI analysis.

══════════════════════════════════════════════════════════════
RISK ASSESSMENT
══════════════════════════════════════════════════════════════

Overall Risk
------------

{threat_level}

Business Impact
---------------

Explain the possible impact based on the supplied analysis.

Severity
--------

Choose one:

- Critical
- High
- Medium
- Low

Likelihood
----------

Choose one:

- High
- Medium
- Low

══════════════════════════════════════════════════════════════
RECOMMENDED MITIGATION
══════════════════════════════════════════════════════════════

Provide five practical mitigation steps.

══════════════════════════════════════════════════════════════
INCIDENT STATUS
══════════════════════════════════════════════════════════════

Current Status
--------------

Choose:

- Open
- Under Investigation
- Closed

Recommended Priority
--------------------

Choose:

- P1
- P2
- P3
- P4

══════════════════════════════════════════════════════════════
END OF REPORT
══════════════════════════════════════════════════════════════

Generated by AI CyberShield
Powered by Machine Learning + Google Gemini AI

Rules:

- Keep the report professional.
- Do not invent evidence.
- Base every section only on the supplied AI analysis.
- Do not repeat the same information.
- Use concise SOC-style language.
"""


# ============================================================
# INCIDENT REPORT GENERATION
# ============================================================

def generate_incident_report(
    analysis,
    analysis_type,
    threat_level,
    threat_type,
    risk_score,
):
    """
    Generate a professional incident report using Gemini.
    """

    incident_id = (
        f"CS-{datetime.now().strftime('%Y%m%d')}-"
        f"{str(uuid.uuid4())[:8].upper()}"
    )

    generated_time = datetime.now().strftime(
        "%d %B %Y %I:%M %p"
    )

    try:

        prompt = incident_report_prompt.format(
            incident_id=incident_id,
            generated_time=generated_time,
            analysis_type=analysis_type,
            threat_level=threat_level,
            threat_type=threat_type,
            risk_score=risk_score,
            analysis=analysis,
        )

        return _generate(prompt)

    except Exception as e:

        print("Incident Report Error:", e)

        raise