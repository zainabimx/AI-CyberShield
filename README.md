# 🛡️ AI CyberShield

### AI-Powered Security Operations Center (SOC) Platform

**AI CyberShield** is a cybersecurity operations platform designed to simulate a modern **Security Operations Center (SOC)** workflow for detecting, analyzing, investigating, and documenting security threats.

The platform combines **machine-learning-based phishing detection, URL/domain security analysis, AI-assisted threat analysis, SOC alert management, incident investigation, analyst notes, MITRE ATT&CK mapping, and automated incident reporting**.

---

## 🚀 Overview

AI CyberShield goes beyond simple threat detection by demonstrating the workflow a security analyst may follow after a suspicious event is identified.

```text
Security Input
      ↓
Threat Detection
      ↓
Risk Scoring
      ↓
SOC Alert Generation
      ↓
Incident Investigation
      ↓
Analyst Disposition
      ↓
Incident Report
      ↓
PDF Export
```

The project was developed as a practical **cybersecurity and AI/ML portfolio project**, focusing on how detection, triage, investigation, and incident documentation can be integrated into a single SOC-style platform.

---

## 🔍 Key Features

### 📧 Email Phishing Detection

Analyzes email content to identify potential phishing attempts using a **machine-learning pipeline** based on:

- **TF-IDF** text vectorization
- **Logistic Regression** classification
- Threat and risk scoring
- Severity classification
- Security indicators

The resulting assessment can be routed into the **SOC alert workflow**.

---

### 🌐 Domain & URL Security Analysis

Analyzes URLs for potentially suspicious characteristics, including:

- Suspicious URL structures
- IP-based URLs
- Obfuscation patterns
- Suspicious domains
- Login and verification indicators
- Potentially malicious URL characteristics

The analysis produces a **risk assessment** that can be incorporated into the SOC workflow.

---

### 🤖 AI-Assisted Threat Analysis

AI CyberShield integrates the **Google Gemini API** to provide AI-assisted analysis of detected threats.

The AI analysis can help provide:

- Threat context
- Analysis of suspicious indicators
- Potential attack behavior
- Security implications
- Analyst-oriented recommendations

The AI component is designed to **assist the analyst rather than replace the underlying detection and SOC workflow**.

---

### 🚨 SOC Alert Management

Detected threats can be converted into persistent **SOC alerts** containing information such as:

- Alert ID
- Timestamp
- Threat type
- Severity
- Priority
- Confidence
- Risk score
- Indicators
- MITRE ATT&CK techniques
- Current status
- Threat summary

---

### 🔎 Incident Investigation

Security analysts can investigate generated alerts and review associated evidence before making a disposition.

Supported workflow states include:

- `OPEN`
- `INVESTIGATING`
- `RESOLVED`

The investigation workflow connects the alert with **analyst notes, status changes, and incident reporting**.

---

### 📝 Analyst Notes

Analysts can record investigation notes associated with incidents.

These notes provide a **persistent record of analyst observations and investigation context** within the SOC workflow.

---

### 📊 Risk & Severity Classification

AI CyberShield maps risk scores to operational severity levels and priorities.

| Risk Score | Severity | Priority |
|------------|----------|----------|
| **85–100** | **CRITICAL** | **P1** |
| **65–84** | **HIGH** | **P2** |
| **40–64** | **MEDIUM** | **P3** |
| **0–39** | **LOW** | **P4** |

This provides a consistent approach to **prioritizing alerts for investigation**.

---

### 📄 Incident Reporting

The platform generates structured incident reports containing:

- Security findings
- Severity
- Verdict
- Incident status
- Analyst notes
- Report metadata

Reports can also be **exported as PDF documents** for incident documentation.

---

### 💾 Persistent SOC Storage

**SQLite** is used to persist SOC information, including:

- Security alerts
- Incident reports
- Analyst notes
- Alert status
- Investigation information

This allows SOC information to remain available across application sessions.

---

## 🏗️ Architecture

```text
                         ┌──────────────────────┐
                         │    Streamlit SOC UI  │
                         └───────────┬──────────┘
                                     │
                    ┌────────────────┼────────────────┐
                    │                │                │
                    ▼                ▼                ▼
             Email Security    Domain Security   SOC Operations
                    │                │                │
                    └────────────────┼────────────────┘
                                     ▼
                            ┌─────────────────┐
                            │  Threat / Risk  │
                            │    Analysis     │
                            └────────┬────────┘
                                     │
                                     ▼
                            ┌─────────────────┐
                            │   SOC Alert     │
                            │    Creation     │
                            └────────┬────────┘
                                     │
                                     ▼
                            ┌─────────────────┐
                            │   Investigation │
                            └────────┬────────┘
                                     │
                     ┌───────────────┴───────────────┐
                     │                               │
                     ▼                               ▼
              Analyst Notes                  Gemini AI Analysis
                     │                               │
                     └───────────────┬───────────────┘
                                     ▼
                            ┌─────────────────┐
                            │ Incident Report │
                            └────────┬────────┘
                                     │
                                     ▼
                              ┌─────────────┐
                              │ PDF Export  │
                              └─────────────┘

                              ┌─────────────┐
                              │    SQLite   │
                              │   Database  │
                              └─────────────┘
```

---

## 🔄 SOC Investigation Workflow

AI CyberShield is designed around an **analyst-oriented workflow**:

### 1. Security Input

The analyst submits a suspicious **email or URL** for analysis.

### 2. Threat Detection

The appropriate detection engine analyzes the submitted input.

### 3. Risk Assessment

The system calculates a **risk score** and assigns a severity and priority.

### 4. SOC Alert Generation

A security event can be recorded as a persistent **SOC alert with a unique Alert ID**.

### 5. Investigation

The analyst reviews the alert evidence and available threat analysis.

### 6. AI-Assisted Analysis

**Gemini AI** can provide additional contextual analysis to assist the investigation.

### 7. Analyst Disposition

The analyst can update the incident status and record investigation notes.

### 8. Incident Reporting

A structured incident report is generated from the investigation.

### 9. PDF Documentation

The completed incident report can be exported as a **PDF document**.

---

## 🧰 Technology Stack

| Technology | Purpose |
|------------|---------|
| **Python** | Core application and security logic |
| **Streamlit** | SOC dashboard and interface |
| **Scikit-learn** | Machine-learning-based detection |
| **TF-IDF** | Email text feature extraction |
| **Logistic Regression** | Phishing classification |
| **Google Gemini API** | AI-assisted threat analysis |
| **SQLite** | Persistent SOC data storage |
| **ReportLab** | PDF incident report generation |
| **Pytest** | Security logic testing |

---

## 📁 Project Structure

```text
AI-CyberShield/
│
├── app.py
├── llm.py
├── pdf_generator.py
├── report_generator.py
├── SOC_UPGRADE_PATCH.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── models/
│   ├── phishing_model.pkl
│   ├── tfidf_vectorizer.pkl
│   ├── website_phishing_model.pkl
│   └── website_feature_importance.csv
│
├── src/
│   ├── analyst_notes.py
│   ├── database.py
│   ├── predict_email.py
│   ├── security_core.py
│   ├── train_model.py
│   ├── website_detector.py
│   └── website_train_model.py
│
├── datasets/
│   ├── phishing_email_/
│   ├── phishing_website_/
│   └── test_dataset.py
│
└── tests/
    └── test_security_core.py
```

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/zainabimx/AI-CyberShield.git
cd AI-CyberShield
```

### 2. Create a virtual environment

#### Windows

```bash
python -m venv venv
venv\Scripts\activate
```

#### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## 🔐 Gemini API Configuration

AI CyberShield uses the **Google Gemini API** for AI-assisted threat analysis.

Create a local `.env` file in the project root:

```env
GOOGLE_API_KEY=YOUR_GEMINI_API_KEY
```

The `.env` file is intentionally excluded from Git through `.gitignore`.

> ⚠️ **Never commit or expose your API key publicly.**

---

## ▶️ Running the Application

Start the Streamlit application:

```bash
streamlit run app.py
```

The application will open in your browser.

---

## 🧪 Testing

The project includes tests for core security functionality.

Run the test suite with:

```bash
pytest
```

---

## 📊 Detection Components

### 📧 Email Detection

The email detection pipeline uses machine learning to classify email content.

```text
Email Payload
      ↓
Text Processing
      ↓
TF-IDF Vectorization
      ↓
Logistic Regression
      ↓
Classification
      ↓
Risk Assessment
```

### 🌐 Website / URL Detection

The website security component evaluates URL characteristics and uses the available detection logic/model to produce a security assessment.

```text
URL
 ↓
Feature Extraction / Analysis
 ↓
Threat Detection
 ↓
Risk Score
 ↓
Severity
 ↓
SOC Alert
```

---

## 🚨 Alert Lifecycle

Each SOC alert follows a structured lifecycle:

```text
OPEN
  │
  ▼
INVESTIGATING
  │
  ▼
RESOLVED
```

The alert remains associated with its **investigation and incident report** throughout the workflow.

---

## 📋 Incident Management

Each incident can contain:

- **Unique Alert ID**
- Detection source
- Threat type
- Risk score
- Severity
- Priority
- Security indicators
- MITRE ATT&CK techniques
- Investigation findings
- Analyst notes
- Incident status
- Incident report
- PDF documentation

This structure is intended to reflect the information an analyst may work with during a security investigation.

---

## 🖥️ Screenshots

Screenshots of the platform can be added below.

### 🏠 SOC Command Center

<img width="1797" height="915" alt="Screenshot 2026-09-14 221738" src="https://github.com/user-attachments/assets/e2dca9b6-1ee8-49b4-b2ec-4368963b4b93" />


### 📧 Email Security

<img width="1802" height="927" alt="Screenshot 2026-09-14 221220" src="https://github.com/user-attachments/assets/d35f5b48-82d6-47d7-84b6-d7b1d513bcc7" />

<img width="1796" height="918" alt="Screenshot 2026-09-14 221317" src="https://github.com/user-attachments/assets/c71bccaf-357d-4f9e-ae28-e520af5c6e8d" />



### 🌐 Domain Security

<img width="1780" height="916" alt="Screenshot 2026-09-14 221441" src="https://github.com/user-attachments/assets/834949f5-4384-41be-b657-7f383132a650" />


### 🚨 Alert Queue

<img width="1807" height="911" alt="Screenshot 2026-09-14 221857" src="https://github.com/user-attachments/assets/54ae8ae9-891a-46ee-b0e6-a99305dae97b" />


### 🔎 Incident Investigation

<img width="1802" height="917" alt="Screenshot 2026-09-14 221925" src="https://github.com/user-attachments/assets/2d491e1c-ecc6-420a-9fca-143dbcd20127" />


### 📄 Incident Reporting

<img width="1797" height="917" alt="Screenshot 2026-09-14 222057" src="https://github.com/user-attachments/assets/abbe5818-c567-4638-9919-3e2e0a967cb1" />


---

## 🎯 Project Objectives

AI CyberShield was developed as a practical cybersecurity project to explore how multiple security components can work together as an **operational SOC workflow**.

The project focuses on:

- Security monitoring concepts
- Phishing detection
- URL/domain security analysis
- Risk-based alert triage
- Incident investigation
- Security analyst workflows
- AI-assisted security analysis
- Persistent SOC data
- Incident documentation

---

## 💡 What I Learned

Through the development of AI CyberShield, I explored practical implementation of:

- Machine-learning-based phishing detection
- Security-focused feature engineering
- Risk scoring and alert prioritization
- SOC-style incident workflows
- AI integration into cybersecurity applications
- Persistent security data management
- Incident report generation
- PDF security documentation
- Python application architecture
- Automated security testing

---

## 🔮 Future Enhancements

Potential future improvements include:

- Real-time log ingestion
- SIEM integrations
- Role-based access control
- Threat-intelligence API integration
- Automated IOC enrichment
- Network traffic analysis
- Malware analysis workflows
- Advanced alert correlation
- Automated SOC playbooks
- Containerized deployment
- Cloud deployment

---

## ⚠️ Disclaimer

AI CyberShield is an **educational and portfolio project** designed for cybersecurity learning and demonstration.

It should not be considered a **production-grade security system** or a replacement for professional security monitoring infrastructure.

Do not submit real confidential emails, credentials, API keys, or sensitive organizational data for analysis.

---

## 👩‍💻 Author

### Zainab Imdad

**Cybersecurity & AI/ML Enthusiast**

GitHub: [github.com/zainabimx](https://github.com/zainabimx)

---

## ⭐ Project

If you find **AI CyberShield** useful or interesting, consider ⭐ **starring the repository**.

> **AI CyberShield — Detect. Investigate. Respond.**
