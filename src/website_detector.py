from urllib.parse import urlparse
import re

def analyze_url(url):

    score = 0
    reasons = []

    # URL Length
    if len(url) > 75:
        score += 20
        reasons.append("Long URL")

    # Too many dots
    if url.count(".") > 3:
        score += 15
        reasons.append("Multiple subdomains")

    # Hyphens
    if "-" in url:
        score += 15
        reasons.append("Contains hyphens")

    # No HTTPS
    if not url.startswith("https://"):
        score += 20
        reasons.append("Not using HTTPS")

    # Suspicious Keywords
    suspicious_words = [
        "login",
        "verify",
        "secure",
        "update",
        "account",
        "bank"
    ]

    for word in suspicious_words:
        if word in url.lower():
            score += 10
            reasons.append(f"Contains '{word}'")

    return score, reasons


url = input("Enter URL:\n")

score, reasons = analyze_url(url)

print("\nRisk Score:", score)

if score >= 50:
    print("⚠️ Potential Phishing Website")
else:
    print("✅ Appears Safe")

print("\nReasons:")

for reason in reasons:
    print("-", reason)