from dotenv import load_dotenv
import os
import time
from datetime import datetime
import uuid

import streamlit as st
from openai import OpenAI


# ============================================================
# ENVIRONMENT
# ============================================================

load_dotenv()


# ============================================================
# OPENROUTER CONFIGURATION
# ============================================================

MODEL_NAME = "google/gemini-3.6-flash"

_api_key = os.getenv("OPENROUTER_API_KEY")

# Streamlit Cloud fallback
if not _api_key:
    try:
        _api_key = st.secrets["OPENROUTER_API_KEY"]
    except Exception:
        _api_key = None


_client = None

if _api_key:
    _client = OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=_api_key,
    )


# ============================================================
# AI GENERATION ENGINE
# ============================================================

def _generate(prompt: str) -> str:
    """
    Send a prompt to Gemini through OpenRouter.

    Includes:
    - API key validation
    - 3000-token response limit
    - Retry handling for temporary errors
    - Clean error reporting
    """

    if _client is None:
        raise RuntimeError(
            "OPENROUTER_API_KEY is not configured."
        )

    last_error = None

    for attempt in range(3):

        try:

            response = _client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {
                        "role": "user",
                        "content": prompt,
                    }
                ],
                temperature=0.3,
                max_tokens=3000,
            )

            # Safely extract response text
            text = response.choices[0].message.content

            if not text:
                raise RuntimeError(
                    "Gemini returned an empty response."
                )

            return text

        except Exception as e:

            last_error = e
            error_text = str(e).upper()

            # Temporary availability / rate-limit errors
            if (
                "503" in error_text
                or "UNAVAILABLE" in error_text
                or "429" in error_text
                or "RATE LIMIT" in error_text
            ):

                # 1 sec -> 2 sec -> 4 sec
                time.sleep(2 ** attempt)
                continue

            # Authentication errors
            if (
                "401" in error_text
                or "403" in error_text
                or "API KEY" in error_text
                or "API_KEY" in error_text
            ):
                raise RuntimeError(
                    "OpenRouter API authentication failed. "
                    "Please verify OPENROUTER_API_KEY."
                )

            # Credit / token limit errors
            if (
                "402" in error_text
                or "CREDITS" in error_text
                or "MAX_TOKENS" in error_text
            ):
                raise RuntimeError(
                    "OpenRouter credits or token limit are "
                    "insufficient for this request."
                )

            # Other errors
            raise

    raise RuntimeError(
        f"AI service temporarily unavailable after "
        f"3 attempts: {last_error}"
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

Use ONLY the evidence supplied above.

Do not invent:

- sender authentication results
- domain reputation
- malware
- attachment contents
- spoofing
- user activity
- successful compromise

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

Important:

- A legitimate ML result does not force a legitimate AI assessment.
- A phishing ML result does not prove phishing by itself.
- Do not claim certainty when the supplied evidence is insufficient.

## Recommended action

Give 2–4 practical next steps appropriate to the evidence.
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

        if (
            "503" in error_text
            or "UNAVAILABLE" in error_text
            or "429" in error_text
            or "RATE LIMIT" in error_text
        ):

            return """
## 🤖 AI Analysis Temporarily Unavailable

The Gemini AI analysis service is temporarily unavailable.

**Detection Status:** Available

**AI Status:** Temporarily unavailable

The underlying machine-learning detection remains available.

Please retry the AI analysis shortly.
"""

        if (
            "402" in error_text
            or "CREDITS" in error_text
            or "MAX_TOKENS" in error_text
        ):

            return """
## ⚠️ AI Analysis Token Limit

The OpenRouter account does not currently have enough
available credits for the requested response size.

**Detection Status:** Available

**AI Status:** Insufficient credits

Please reduce the requested response size or add credits
to the OpenRouter account.
"""

        if (
            "401" in error_text
            or "403" in error_text
            or "API KEY" in error_text
            or "API_KEY" in error_text
        ):

            return """
## ⚠️ AI Analysis Configuration Error

The Gemini AI analysis engine could not authenticate
through OpenRouter.

**Detection Status:** Available

**AI Status:** Authentication error

Please verify the OPENROUTER_API_KEY configuration.
"""

        return f"""
## 🤖 AI Analysis Unavailable

The AI enrichment service could not complete the analysis.

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

Your task is to generate a professional cybersecurity assessment
based ONLY on the information provided.

Never invent facts.

Never speculate about hypothetical situations.

Do not assume indicators that are not provided.

Base every conclusion only on the supplied URL, heuristic score
and detected indicators.

----------------------------------------
IF Verdict = HIGH RISK
----------------------------------------

Generate the report using this format exactly:

# 🌐 AI Website Threat Analysis

## Threat Level

High

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

Explain realistic risks supported by the detected indicators.

Do not claim that malware or credential theft is confirmed
unless the supplied evidence establishes it.

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

Low Risk

## Website Assessment

Explain why the website appears safe based on the heuristic analysis.

## Positive Security Indicators

List only the positive indicators actually observed.

## Good Security Practices

Provide 3–5 general cybersecurity tips for safely browsing
legitimate websites.

## Executive Summary

Summarize why the website currently appears safe.

----------------------------------------
IMPORTANT RULES
----------------------------------------

- Never generate hypothetical attack scenarios.
- Never invent security indicators.
- Never claim a website is malicious without supporting evidence.
- Keep the response concise and professional.
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

        if (
            "503" in error_text
            or "UNAVAILABLE" in error_text
            or "429" in error_text
            or "RATE LIMIT" in error_text
        ):

            return """
## 🤖 AI Analysis Temporarily Unavailable

The Gemini AI analysis service is temporarily unavailable.

**Detection Status:** Available

**AI Status:** Temporarily unavailable

The underlying website security detection remains available.

Please retry the AI analysis shortly.
"""

        if (
            "402" in error_text
            or "CREDITS" in error_text
            or "MAX_TOKENS" in error_text
        ):

            return """
## ⚠️ AI Analysis Token Limit

The OpenRouter account does not currently have enough
available credits for the requested response size.

**Detection Status:** Available

**AI Status:** Insufficient credits

Please reduce the requested response size or add credits
to the OpenRouter account.
"""

        if (
            "401" in error_text
            or "403" in error_text
            or "API KEY" in error_text
            or "API_KEY" in error_text
        ):

            return """
## ⚠️ AI Analysis Configuration Error

The Gemini AI analysis engine could not authenticate
through OpenRouter.

**Detection Status:** Available

**AI Status:** Authentication error

Please verify the OPENROUTER_API_KEY configuration.
"""

        return f"""
## 🤖 AI Analysis Unavailable

The AI enrichment service could not complete the analysis.

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

    incident_id = (
        f"CS-{datetime.now().strftime('%Y%m%d')}-"
        f"{str(uuid.uuid4())[:8].upper()}"
    )

    generated_time = datetime.now().strftime(
        "%d %B %Y %I:%M %p"
    )

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