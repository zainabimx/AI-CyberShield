"""Deterministic SOC helpers: IOC extraction, alerting and MITRE mapping."""
from __future__ import annotations
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib, re
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s<>\"]+", re.I)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")

@dataclass
class SecurityAlert:
    alert_id: str
    timestamp: str
    source: str
    threat_type: str
    severity: str
    priority: str
    confidence: float
    risk_score: int
    status: str
    indicators: list[str]
    mitre_techniques: list[dict[str, str]]
    summary: str

def extract_iocs(text: str) -> dict[str, list[str]]:
    text = str(text or "")
    urls = sorted(set(u.rstrip(".,);]") for u in URL_RE.findall(text)))
    emails = sorted(set(EMAIL_RE.findall(text)))
    ips = sorted(set(IP_RE.findall(text)))
    hashes = sorted(set(HASH_RE.findall(text)))
    domains = set()
    for url in urls:
        try:
            host = urlparse(url).hostname
            if host: domains.add(host.lower())
        except ValueError:
            pass
    return {"urls": urls, "domains": sorted(domains), "ip_addresses": ips,
            "email_addresses": emails, "file_hashes": hashes}

def mitre_mapping(threat_type: str, indicators=None):
    t = (threat_type or "").lower(); indicators = indicators or []
    out = []
    if "phishing" in t:
        out.append({"id":"T1566","name":"Phishing","reason":"Phishing-style initial access vector."})
    if "credential" in t or "login" in t:
        out.append({"id":"T1566.002","name":"Phishing: Spearphishing Link","reason":"Credential-oriented phishing involving a link."})
    if "attachment" in t or any("attachment" in str(x).lower() for x in indicators):
        out.append({"id":"T1566.001","name":"Phishing: Spearphishing Attachment","reason":"Evidence indicates an attachment-based phishing vector."})
    if "brute" in t:
        out.append({"id":"T1110","name":"Brute Force","reason":"Repeated authentication failures can indicate password guessing."})
    seen=set(); return [x for x in out if not (x["id"] in seen or seen.add(x["id"]))]

def severity_from_score(score):
    """Return the canonical SOC severity and priority for a 0-100 risk score."""
    score = max(0, min(100, int(float(score))))
    if score >= 85: return "CRITICAL", "P1"
    if score >= 65: return "HIGH", "P2"
    if score >= 40: return "MEDIUM", "P3"
    return "LOW", "P4"


# Backward-compatible alias for existing callers.
def _severity(score):
    return severity_from_score(score)

def create_alert(*, source, threat_type, confidence, risk_score, indicators, summary):
    score = max(0, min(100, int(risk_score))); severity, priority = _severity(score)
    stamp = datetime.now(timezone.utc); digest = hashlib.sha256(
        f"{stamp.isoformat()}|{source}|{threat_type}|{summary}".encode()).hexdigest()[:8].upper()
    return asdict(SecurityAlert(
        alert_id=f"CS-{stamp.strftime('%Y%m%d')}-{digest}", timestamp=stamp.isoformat(timespec="seconds"),
        source=source, threat_type=threat_type, severity=severity, priority=priority,
        confidence=round(float(confidence),2), risk_score=score, status="OPEN",
        indicators=list(dict.fromkeys(indicators)), mitre_techniques=mitre_mapping(threat_type, indicators),
        summary=summary))
