# AI CyberShield — SOC Upgrade

AI-assisted phishing and malicious URL detection platform extended toward a junior SOC workflow.

## Existing detection
- Phishing email classification: TF-IDF + Logistic Regression
- URL heuristic analysis
- Gemini-assisted security analysis
- Incident/PDF reporting

## New SOC foundation
- IOC extraction (URLs, domains, IPs, emails, hashes)
- SOC alerts with severity and priority
- Incident status lifecycle
- MITRE ATT&CK mapping
- Alert queue and incident-investigation UI patch
- Secret-management hygiene
- Unit tests

## Run

```bash
pip install -r requirements.txt
streamlit run app.py
```

Create `.env` locally from `.env.example`; never commit `.env`.

## Next milestones
1. Threat-intelligence enrichment for domains/IPs/hashes.
2. Windows/Linux/authentication log analyzer.
3. Isolation Forest anomaly detection.
4. Explainable ML.
5. Persistent database-backed case management.
