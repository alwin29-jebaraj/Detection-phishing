# AI-Powered Phishing Investigation Lab

An educational cybersecurity threat analysis platform that evaluates emails and URLs for phishing indicators with **explainable scoring**, transparent evidence breakdowns, URL heuristics, modular AI/NLP synthesis, **multi-turn Gemini AI chat**, and **professional PDF incident reports**.

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

## 2. Key Features

- **Multi-Vector Analysis:**
  - **Email Investigation:** Analyzes headers (Subject, From, Reply-To), body text, urgency patterns, threat statements, credential lures, and financial solicitations.
  - **URL Investigation:** Static-only inspection of 15+ structural indicators including protocol, IPv4 hosts, subdomain depth, hyphen abuse, character obfuscation (`@`, `%`), suspicious TLDs, and keyword clustering.
- **Explainable Scoring System:**
  - 4 transparent risk tiers: **LOW** (0–24), **MEDIUM** (25–49), **HIGH** (50–74), and **CRITICAL** (75–100).
  - Itemized mathematical ledger detailing every point contribution with matched text evidence.
- **Interactive Multi-Turn Gemini AI Chatbot:**
  - Connected via `@google/genai` on the backend (`POST /api/chat`).
  - Supports **Gemini 3.5 Flash** for general reasoning and **Gemini 3.1 Flash Lite** for high-speed queries.
  - Dynamically passes the active check context so users can ask specific questions about the flagged email or link.
  - Suggests defensive action plans, drafts employee warning alerts, and answers cybersecurity hygiene questions.
- **Professional PDF Report Generator:**
  - Client-side vector PDF generation powered by `jspdf`.
  - Generates polished documentation with incident header, risk score summary badge, executive threat briefing, itemized indicator table, and standardized ASCII report archival block.
- **Dual-Engine Architecture:**
  - **Deterministic Rule Engine:** Guaranteed, offline-capable analysis that operates reliably without cloud dependencies.
  - **AI/NLP Synthesis:** Translates structured rule findings into conversational threat briefings without overriding the deterministic score.
- **Audit History & Database:**
  - SQLite persistent storage logging past investigations, timestamps, risk classifications, and indicators without storing user passwords or private tokens.
  - Search by keyword or ID, filter by risk severity, and inspect or export past records.
- **Live Automated Unit Test Suite:**
  - Integrated verification suite running 18 Python tests in milliseconds covering urgency regexes, suspension threats, credential lures, URL heuristics, and scoring formula verification.

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
  [ AI / NLP Synthesis Engine ] (Gemini 3.5 Flash / 3.8 Flash or Deterministic Fallback)
              ↓
  [ Multi-Turn Gemini Chatbot & Professional PDF Generator & SQLite Persistence ]
```

---

## 4. Technology Stack

- **Frontend:** React 19, TypeScript, Tailwind CSS, Lucide Icons, `jspdf`
- **Backend Server:** Node.js, Express, `tsx`, `@google/genai` SDK
- **Python Forensic Engine:** Python 3.10+, Flask 3.0+, `unittest`
- **Database:** SQLite3 (`phishing_lab.db`)
- **AI Models:** Google Gemini 3.5 Flash & Gemini 3.1 Flash Lite

---

## 5. Project Directory Structure

```text
phishing-investigation-lab/
├── src/
│   ├── App.tsx                    # Main React UI with Checker, Chat, History, Tests, & PDF
│   ├── main.tsx                   # React client mounting entrypoint
│   └── index.css                  # Tailwind styles and custom utilities
├── server.ts                      # Express API server & Gemini SDK bridge
├── app.py                         # Flask REST API & Web Application entrypoint
├── database/
│   ├── __init__.py
│   └── database.py                # SQLite schema, migrations, and query helpers
├── analyzers/
│   ├── __init__.py
│   ├── indicator_extractor.py     # Regex tokenizer, email headers, URL extraction
│   ├── rule_engine.py             # Deterministic urgency, threat & credential rules
│   ├── url_analyzer.py            # Static structural URL heuristics & TLD parser
│   └── ai_analyzer.py             # Gemini AI synthesis with deterministic fallback
├── scoring/
│   ├── __init__.py
│   └── risk_scorer.py             # Explainable scoring calculation & ASCII reports
├── models/
│   ├── __init__.py
│   └── analysis.py                # Dataclasses (Indicator, URLAnalysisResult, etc.)
├── tests/
│   ├── __init__.py
│   ├── test_rules.py              # Rule engine unit tests
│   ├── test_url_analyzer.py       # URL heuristics unit tests
│   └── test_scoring.py            # Scoring formula and synthetic case tests
├── package.json                   # Node.js dependencies & scripts
├── requirements.txt               # Production Python dependencies
├── Procfile                       # Deployment configuration
└── README.md                      # Complete documentation & operational manual
```

---

## 6. Installation & Running Locally

### Node.js / React Full-Stack Environment

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/phishing-investigation-lab.git
   cd phishing-investigation-lab
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Configure Environment Variables (Optional):**
   ```bash
   export GEMINI_API_KEY="your-gemini-api-key"
   ```

4. **Start the development server:**
   ```bash
   npm run dev
   ```
   Navigate to `http://localhost:3000`.

### Python Automated Unit Tests

To run the complete automated test suite:

```bash
python3 -m unittest discover tests
```

Output:
```text
..................
----------------------------------------------------------------------
Ran 18 tests in 0.009s

OK
```

---

## 7. Security Limitations & Educational Scope

- **Static Heuristics Only:** This tool does not execute JavaScript, establish socket connections, or trigger active web crawling.
- **Evasion Caveat:** Advanced persistent threats (APTs) using legitimate compromised infrastructure or zero-day obfuscation may not be caught by static heuristics alone.
- **Privacy Assurance:** Submitted text is never sent to third-party tracking services or stored in external telemetry aggregators.
