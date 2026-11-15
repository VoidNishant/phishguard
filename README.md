# 🛡️ PhishGuard: Cybersecurity Phishing URL Detector

A minor cybersecurity project built in Python featuring **Lexical Analysis**, **13 Cybersecurity Heuristic Rules**, and **Machine Learning** (Random Forest) to detect malicious phishing URLs, wrapped in an interactive **Streamlit** web application.

---

## 📌 Project Overview
Phishing remains the #1 initial access vector in cyber attacks (MITRE ATT&CK T1566). Attackers craft deceptively structured URLs using typosquatting, IDN homoglyphs, free/abuse-prone TLDs, IP hostnames, userinfo `@` credential tricks, and nested subdomains to deceive victims.

**PhishGuard** implements a **defense-in-depth hybrid architecture**:
1. **Cybersecurity Heuristic Rules Engine:** Evaluates URLs against 13 deterministic security indicators derived from RFC 3986, OWASP, and APWG recommendations.
2. **Machine Learning Classifier:** A Random Forest model trained on 22 lexical, structural, and behavioral features to capture statistical anomaly patterns.
3. **Streamlit Web Application:** A dashboard providing single-URL deep inspections, bulk batch scanning with file upload, CSV report downloads, and a cybersecurity knowledge base.

---

## 🚀 Key Features

- **🔎 Real-Time Single URL Inspector:**
  - One-click presets for quick testing (Google search, IP attack, brand spoofing, IDN homograph / Punycode).
  - Multi-metric scoring: Composite Risk Score (0–100%), Heuristic Score, and ML Probability.
  - Structural URL dissection (Scheme, Hostname, Subdomain depth, Registered Domain, TLD, Port, Path, Query).
- **🛡️ Explainable Cybersecurity Audit:**
  - Flags specific triggered rules with severity badges (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
  - Provides root-cause evidence and security rationale for each triggered rule.
  - Public Suffix & multi-part ccTLD aware (eliminates false positives on `.co.uk`, `.com.au`, `.co.in`).
  - Reputable platform whitelisting (prevents false positives on Wikipedia, GitHub, etc.).
- **📋 Batch Threat Assessment:**
  - Scan multiple URLs in bulk via text area or file upload (`.txt` / `.csv`).
  - Summary metrics and downloadable CSV audit reports for security analysts.
- **📚 Cybersecurity Knowledge Base:**
  - Explains common URL attack vectors (IDN homograph attacks, RFC 3986 `@` abuse, combosquatting, TLD abuse, subdomain chaining).
  - Defensive recommendations (FIDO2 MFA, origin domain verification).

---

## 🗂️ Project Structure

```text
phishguard/
├── .venv/                   # Python virtual environment
├── features.py              # 22 Lexical, structural & domain feature extractors
├── heuristics.py            # 13 Cybersecurity heuristic rules & risk scoring
├── train_model.py           # Model training & feature evaluation script
├── detector.py              # Hybrid engine coordinating heuristics + ML
├── app.py                   # Streamlit web application
├── model.joblib             # Exported Random Forest model artifact
├── test_detector.py         # 12-point automated unit & regression test suite
├── run.bat                  # One-click Windows launcher
├── requirements.txt         # Project dependencies
└── README.md                # Project documentation
```

---

## ⚙️ Quick Start

Double-click **`run.bat`** — that's it. On the first run it automatically creates `.venv`, installs the pinned dependencies, applies the Smart App Control workaround if needed, and launches the app at `http://localhost:8501`. Subsequent runs start immediately.

## 📦 Setup on Another Laptop

1. Install **Python 3.12** from <https://www.python.org/downloads/> and tick **"Add python.exe to PATH"**.
2. **Before extracting**, right-click the received zip → **Properties** → tick **Unblock** → **Apply** → **OK**. This removes the "from the web" mark so Smart App Control doesn't block `run.bat`.
3. Extract the zip (do **not** include `.venv` when creating the zip — it contains absolute paths and won't work on another machine).
4. Double-click **`run.bat`** — it creates `.venv`, installs dependencies, auto-applies the Smart App Control workaround, and starts the app.
5. If SmartScreen warns, click **More info → Run anyway**.

`run.bat` is the only batch file needed; it handles setup and launch together.

---

## 🔬 Cybersecurity Rules Implemented (13 Rules)

| Rule ID | Indicator | Severity | Cybersecurity Context |
| :--- | :--- | :--- | :--- |
| `R_PSEUDO_PROTOCOL` | Client-Side Script Scheme | Critical | Blocks `javascript:`, `data:`, `vbscript:` used for DOM XSS / payloads. |
| `R_PUNYCODE_HOMOGRAPH`| IDN Homograph / Punycode | Critical | Detects `xn--` or lookalike Cyrillic/Greek characters mimicking real brands. |
| `R_BRAND_SPOOF` | Brand Spoofing | Critical | High-value brands (PayPal, Apple, Google) placed in subdomains of untrusted domains. |
| `R_AT_SYMBOL` | `@` in Authority | Critical | RFC 3986 treats everything before `@` as credentials; browser routes to host after `@`. |
| `R_IP_HOST` | IP Hostname | High | Attackers use raw IPs to bypass domain reputation blocklists. |
| `R_NO_HTTPS_SENSITIVE`| Insecure HTTP Auth | High | Transmitting credentials or banking keywords over unencrypted HTTP. |
| `R_NON_STANDARD_PORT` | Port Anomaly | High | Phishing servers operating on non-standard ports (e.g. 4444, 8888, 3000). |
| `R_EXCESS_SUBDOMAIN` | Subdomain Depth | High | Deep chains (e.g. `login.paypal.com.attacker.com`) hide actual domains on mobile browsers. |
| `R_DOUBLE_SLASH` | Path Redirection `//` | High | Open redirect tricks or proxy traversal. |
| `R_SHORTENER` | URL Shortener | Medium | Conceals real target destination (e.g. `bit.ly`, `tinyurl.com`). |
| `R_SUSP_TLD` | Suspicious TLD | Medium | Abuse-prone or free TLDs (`.xyz`, `.top`, `.tk`, `.buzz`). |
| `R_SUSP_HYPHENS` | Combosquatting Hyphens| Medium | Hyphen-stuffed domains mimicking legitimate services (`chase-secure-update.com`). |
| `R_HEX_OBFUSCATION` | Percent Obfuscation | Medium | Obfuscated hex characters to bypass standard pattern filters. |
| `R_EXCESS_LENGTH` | Abnormally Long URL | Low | Parameter padding with tracking tokens or base64 payloads. |

---

## 🛡️ Educational & Research Disclaimer
This project is built for educational, academic, and cybersecurity auditing purposes.
