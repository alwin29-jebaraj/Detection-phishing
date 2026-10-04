# AI-Powered Phishing Investigation Lab

An educational cybersecurity threat analysis platform that evaluates emails and URLs for phishing indicators with **explainable scoring**, transparent evidence breakdowns, URL heuristics, and modular AI/NLP synthesis.

---

## 1. Project Overview

Phishing detection systems in enterprise Security Operations Centers (SOCs) are often criticized for operating as black boxes—outputting an opaque "Phishing Probability: 93%" without articulating the underlying justification.

The **AI-Powered Phishing Investigation Lab** is engineered around the principle of **Explainability Over Black-Box Classification**. For every evaluated message or link, the platform answers:
1. **What was detected?** (Urgent language, account suspension threats, credential prompts, suspicious domains)
2. **Where was it detected?** (Exact in-context evidence snippets and matched strings)
3. **Why is it suspicious?** (Clear psychological manipulation and evasion heuristics)
4. **How was the score calculated?** (Deterministic additive point breakdown capped at 100)
5. **What should the user do?** (Actionable, context-aware defensive recommendations)

> **Educational Safety Notice:**  
> This application uses only safe, synthetic examples. It does not contain credential-harvesting infrastructure, exploits, or malicious payloads, and strictly employs static heuristics without executing or fetching external URLs.

---

## 2. Features

- **Multi-Vector Analysis:**
  - **Email Investigation:** Analyzes headers (Subject, From, Reply-To), body text, urgency patterns, threat statements, credential lures, and financial solicitations.
  - **URL Investigation:** Static-only inspection of 15+ structural indicators including protocol, IPv4 hosts, subdomain depth, hyphen abuse, character obfuscation (`@`, `%`), suspicious TLDs, and keyword clustering.
- **Explainable Scoring System:**
  - 4 transparent risk tiers: **LOW** (0–24), **MEDIUM** (25–49), **HIGH** (50–74), and **CRITICAL** (75–100).
  - Itemized mathematical ledger detailing every point contribution with matched text evidence.
- **Dual-Engine Architecture:**
  - **Deterministic Rule Engine:** Guaranteed, offline-capable analysis that operates reliably without cloud dependencies.
  - **AI/NLP Synthesis (Gemini 3.8 Flash):** Translates structured rule findings into conversational threat briefings without overriding the deterministic score.
- **Forensic Report Generation:**
  - Generates standardized ASCII Phishing Analysis Reports formatted for SOC incident ticketing systems.
- **Audit History & Database:**
  - SQLite persistent storage logging past investigations, timestamps, risk classifications, and indicators without storing user passwords or private tokens.
- **Live Automated Unit Test Suite:**
  - Integrated verification suite validating urgency, threats, credential requests, URL heuristics, and synthetic test cases.

---

## 3. Architecture Pipeline

```text
[ Email Message or URL Input ]
              ↓
  [ Indicator Extraction ] (Regex, Header Parser, URL Tokenizer)
              ↓
    [ Rule Engine ]  ←→  [ URL Heuristic Analyzer ]
              ↓
  [ Explainable Risk Scorer ] (Calculates 0-100 Score & Point Breakdown)
              ↓
  [ AI / NLP Synthesis Engine ] (Gemini 3.8 Flash or Deterministic Fallback)
              ↓
  [ Standardized Phishing Analysis Report & SQLite Persistence ]
```

---

## 4. Technology Stack

- **Backend:** Python 3.10+, Flask 3.0+, Werkzeug
- **AI/NLP:** Google GenAI SDK (`gemini-3.8-flash`) with automatic offline deterministic fallback
- **Database:** SQLite3
- **Frontend:** Responsive Cybersecurity SOC Interface (HTML5, CSS3, Modern Dark Theme, Vanilla JS / React)
- **Deployment:** Render (configured via `Procfile` and `gunicorn`)
- **Testing:** Python `unittest` test suite

---

## 5. Project Directory Structure

```text
phishing-investigation-lab/
├── app.py                         # Flask REST API & Web Application entrypoint
├── requirements.txt               # Production Python dependencies
├── Procfile                       # Render deployment configuration
├── README.md                      # Complete documentation & operational manual
├── .gitignore                     # Git ignore rules
│
├── database/
│   ├── __init__.py
│   └── database.py                # SQLite schema, migrations, and query helpers
│
├── analyzers/
│   ├── __init__.py
│   ├── indicator_extractor.py     # Regex tokenizer, email headers, URL extraction
│   ├── rule_engine.py             # Deterministic urgency, threat & credential rules
│   ├── url_analyzer.py            # Static structural URL heuristics & TLD parser
│   └── ai_analyzer.py             # Gemini AI synthesis with deterministic fallback
│
├── scoring/
│   ├── __init__.py
│   └── risk_scorer.py             # Explainable scoring calculation & ASCII reports
│
├── models/
│   ├── __init__.py
│   └── analysis.py                # Dataclasses (Indicator, URLAnalysisResult, etc.)
│
├── templates/
│   ├── index.html                 # Flask investigation console template
│   └── history.html               # Flask audit history template
│
├── static/
│   ├── css/style.css              # Cyber SOC dark aesthetic styling
│   └── js/app.js                  # Frontend state machine and API client
│
└── tests/
    ├── __init__.py
    ├── test_rules.py              # Rule engine unit tests
    ├── test_url_analyzer.py       # URL heuristics unit tests
    └── test_scoring.py            # Scoring formula and synthetic case tests
```

---

## 6. Installation & Running Locally (Python / Flask)

### Prerequisites
- Python 3.10 or higher
- Git

### Steps

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/phishing-investigation-lab.git
   cd phishing-investigation-lab
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate   # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Environment Variables (Optional for AI features):**
   ```bash
   export GEMINI_API_KEY="your-gemini-api-key"
   ```
   *(Note: If `GEMINI_API_KEY` is omitted, the application seamlessly runs using its built-in deterministic NLP synthesizer).*

5. **Run the application:**
   ```bash
   python app.py
   ```

6. **Access in browser:**
   Navigate to `http://localhost:5000`.

---

## 7. REST API Documentation

### 1. Analyze Email
- **Endpoint:** `POST /api/analyze/email`
- **Payload:**
  ```json
  {
    "content": "Subject: Urgent: Your Account Will Be Suspended\nDear Customer...\nhttps://secure-account-verification.example.com/login"
  }
  ```
- **Response:**
  ```json
  {
    "id": 1,
    "input_type": "email",
    "risk_score": 87,
    "risk_level": "HIGH",
    "indicators": [
      {
        "indicator": "Urgent language",
        "category": "urgency",
        "severity": "medium",
        "points": 12,
        "evidence": "\"immediately\" in: ...Verify your account immediately using the link below:..."
      }
    ],
    "score_breakdown": [
      { "indicator": "Urgent language", "points": 12, "evidence": "..." }
    ],
    "ai_explanation": {
      "short_explanation": "...",
      "main_suspicious_behavior": "...",
      "most_important_indicators": ["..."],
      "recommended_action": "..."
    },
    "recommendation": "DO NOT click any embedded links..."
  }
  ```

### 2. Analyze URL
- **Endpoint:** `POST /api/analyze/url`
- **Payload:**
  ```json
  {
    "url": "https://secure-account-verification.example.com/login"
  }
  ```

### 3. Get Analysis History
- **Endpoint:** `GET /api/history?limit=50&offset=0`

### 4. Get Investigation Detail
- **Endpoint:** `GET /api/history/<id>`

### 5. Health Check
- **Endpoint:** `GET /api/health`

---

## 8. Database Structure

Stored in SQLite (`phishing_lab.db`):

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PRIMARY KEY | Unique auto-incremented investigation identifier |
| `input_type` | TEXT | Analysis category (`email` or `url`) |
| `input_data` | TEXT | Sanitized excerpt of analyzed input |
| `risk_score` | INTEGER | Final capped score (0–100) |
| `risk_level` | TEXT | Category label (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) |
| `indicators_json` | TEXT (JSON) | Serialized list of detected indicator objects |
| `score_breakdown_json` | TEXT (JSON) | Array of itemized point adjustments |
| `url_analysis_json` | TEXT (JSON) | Structured results from static URL inspection |
| `ai_explanation_json` | TEXT (JSON) | Natural language synthesis generated by AI/fallback |
| `recommendation` | TEXT | Actionable defensive protocol for the user |
| `created_at` | DATETIME | Timestamp of investigation |

---

## 9. Running Tests

To run the complete automated test suite:

```bash
python3 -m unittest discover tests
```

Output:
```text
Ran 18 tests in 0.008s
OK
```

---

## 10. Render Deployment Instructions

This application is ready for zero-configuration deployment to [Render](https://render.com):

1. Push your repository to **GitHub**.
2. Log in to the [Render Dashboard](https://dashboard.render.com).
3. Click **New +** → **Web Service**.
4. Connect your GitHub repository.
5. Configure the build parameters:
   - **Environment:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app`
6. *(Optional)* Add Environment Variable:
   - Key: `GEMINI_API_KEY`
   - Value: `your-api-key`
7. Click **Create Web Service**. Render will provision and launch the service with automatic SSL certificate management.

---

## 11. Security Limitations & Educational Scope

- **Static Heuristics Only:** This tool does not execute JavaScript, establish socket connections, or trigger active web crawling.
- **Evasion Caveat:** Advanced persistent threats (APTs) using legitimate compromised infrastructure or zero-day obfuscation may not be caught by static heuristics alone.
- **Privacy Assurance:** Submitted text is never sent to third-party tracking services or stored in external telemetry aggregators.

---

## 12. Future Improvements

- Add SPF, DKIM, and DMARC DNS record lookup integration for live header validation.
- Implement optical character recognition (OCR) for embedded screenshot and QR-code (quishing) lures.
- Export to STIX 2.1 / TAXII feeds for SOC SIEM integration.
