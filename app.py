"""
AI-Powered Phishing Investigation Lab
Flask REST API & Web Application
"""
import os
import json
import subprocess
from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv

from database.database import (
    init_db, save_analysis, get_history,
    get_analysis_by_id, delete_analysis, get_stats
)
from analyzers.rule_engine import run_email_rules
from analyzers.url_analyzer import analyze_url
from analyzers.indicator_extractor import sanitize_input
from analyzers.ai_analyzer import generate_ai_explanation
from scoring.risk_scorer import calculate_risk_score, generate_recommendation, generate_text_report

load_dotenv()

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# Initialize the database on startup
init_db()

SYNTHETIC_TEST_CASES = [
    {
        "id": "high-risk-urgent-suspension",
        "title": "Test 1 — Urgent Account Suspension (High Risk)",
        "type": "email",
        "description": "Fabricated suspension notice claiming unusual activity with urgency deadline and deceptive verification portal link.",
        "content": """Subject: Urgent: Your Account Will Be Suspended

Dear Customer,

Your account will be suspended today due to unusual activity. Verify your account immediately using the link below:

https://secure-account-verification.example.com/login

Failure to verify will result in permanent suspension."""
    },
    {
        "id": "medium-risk-activity-review",
        "title": "Test 2 — Account Activity Review (Medium Risk)",
        "type": "email",
        "description": "Notification alleging an unrecognized login with a request to review activity and update details.",
        "content": """Subject: Account Security Review Notification

Hello user,

We noticed a login from an unfamiliar device. Please review your account activity.
Click here to update your information if this was not you:
https://portal-notice.example.com/security/review"""
    },
    {
        "id": "low-risk-engineering-memo",
        "title": "Test 3 — Routine Internal Newsletter (Low Risk)",
        "type": "email",
        "description": "Normal organizational update without urgent pressure, credential demands, or malicious heuristics.",
        "content": """Subject: Weekly Team Engineering Digest #42

Hello everyone,

Here is our weekly project digest. Sprint planning begins Tuesday at 10:00 AM UTC.
Please review the architectural RFC doc on our internal engineering wiki when you have time.

Best regards,
Engineering Operations Team"""
    },
    {
        "id": "url-suspicious-ip-host",
        "title": "Test 4 — Raw IP + Credential Path (URL)",
        "type": "url",
        "description": "Suspicious raw IPv4 hostname targeting login and account verification paths.",
        "content": "http://192.168.1.100/secure-account/verify/login.php"
    },
    {
        "id": "url-brand-impersonation",
        "title": "Test 5 — Brand Subdomain Impersonation (URL)",
        "type": "url",
        "description": "Multi-hyphenated brand name spoofing in subdomain chain.",
        "content": "https://paypal-security-account-verification.attacker-host.com/signin"
    },
    {
        "id": "url-clean-official",
        "title": "Test 6 — Standard Clean HTTPS (URL)",
        "type": "url",
        "description": "Legitimate, clean HTTPS endpoint with normal path structure.",
        "content": "https://example.com/resources/documentation"
    }
]

@app.route('/')
def index_view():
    return render_template('index.html')

@app.route('/history')
def history_view():
    return render_template('history.html')

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "service": "AI-Powered Phishing Investigation Lab",
        "version": "1.0.0",
        "ai_configured": bool(os.environ.get("GEMINI_API_KEY"))
    })

@app.route('/api/stats', methods=['GET'])
def stats_endpoint():
    try:
        stats = get_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": f"Failed to retrieve stats: {str(e)}"}), 500

@app.route('/api/test-cases', methods=['GET'])
def test_cases_endpoint():
    return jsonify(SYNTHETIC_TEST_CASES)

@app.route('/api/analyze/email', methods=['POST'])
def analyze_email_endpoint():
    try:
        data = request.get_json(force=True, silent=True) or {}
        email_text = data.get('content') or data.get('text') or ''
        
        if not email_text or not email_text.strip():
            return jsonify({"error": "Email content is required."}), 400

        sanitized_text = sanitize_input(email_text.strip())
        
        # 1. Indicator Extraction & Rule Engine
        indicators, extracted_urls = run_email_rules(sanitized_text)
        
        # 2. Score Calculation
        risk_score, risk_level, score_breakdown = calculate_risk_score(indicators)
        
        # 3. Dedicated URL analysis for the first extracted URL if any
        primary_url_analysis = None
        if extracted_urls:
            primary_url_analysis = analyze_url(extracted_urls[0]).to_dict()

        # 4. Actionable recommendation
        recommendation = generate_recommendation(risk_level, indicators)

        # 5. AI / NLP Explanation (modular)
        indicator_dicts = [ind.to_dict() for ind in indicators]
        ai_explanation = generate_ai_explanation(
            text=sanitized_text,
            rule_indicators=indicator_dicts,
            url_analysis=primary_url_analysis or {},
            risk_score=risk_score,
            risk_level=risk_level
        )

        # 6. Formatted ASCII Report
        ascii_report = generate_text_report(
            input_type="email",
            input_data=sanitized_text,
            risk_score=risk_score,
            risk_level=risk_level,
            indicators=indicators,
            recommendation=recommendation,
            ai_summary=ai_explanation.get("short_explanation", "")
        )

        # 7. Persist to SQLite Database
        saved_id = save_analysis(
            input_type="email",
            input_data=sanitized_text,
            risk_score=risk_score,
            risk_level=risk_level,
            indicators=indicator_dicts,
            score_breakdown=score_breakdown,
            url_analysis=primary_url_analysis,
            ai_explanation=ai_explanation,
            recommendation=recommendation
        )

        return jsonify({
            "id": saved_id,
            "input_type": "email",
            "input_data": sanitized_text,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "indicators": indicator_dicts,
            "score_breakdown": score_breakdown,
            "extracted_urls": extracted_urls,
            "url_analysis": primary_url_analysis,
            "ai_explanation": ai_explanation,
            "recommendation": recommendation,
            "ascii_report": ascii_report
        })

    except Exception as e:
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500

@app.route('/api/analyze/url', methods=['POST'])
def analyze_url_endpoint():
    try:
        data = request.get_json(force=True, silent=True) or {}
        target_url = data.get('url') or data.get('content') or ''
        
        if not target_url or not target_url.strip():
            return jsonify({"error": "Target URL is required."}), 400

        sanitized_url = sanitize_input(target_url.strip())
        
        # 1. URL Analysis Heuristics
        url_result = analyze_url(sanitized_url)
        indicators = url_result.indicators
        
        # 2. Risk Score & Breakdown
        risk_score, risk_level, score_breakdown = calculate_risk_score(indicators)
        
        # 3. Recommendation
        recommendation = generate_recommendation(risk_level, indicators)

        # 4. AI Explanation
        indicator_dicts = [ind.to_dict() for ind in indicators]
        url_dict = url_result.to_dict()
        ai_explanation = generate_ai_explanation(
            text=sanitized_url,
            rule_indicators=indicator_dicts,
            url_analysis=url_dict,
            risk_score=risk_score,
            risk_level=risk_level
        )

        # 5. Formatted ASCII Report
        ascii_report = generate_text_report(
            input_type="url",
            input_data=sanitized_url,
            risk_score=risk_score,
            risk_level=risk_level,
            indicators=indicators,
            recommendation=recommendation,
            ai_summary=ai_explanation.get("short_explanation", "")
        )

        # 6. Persist to SQLite
        saved_id = save_analysis(
            input_type="url",
            input_data=sanitized_url,
            risk_score=risk_score,
            risk_level=risk_level,
            indicators=indicator_dicts,
            score_breakdown=score_breakdown,
            url_analysis=url_dict,
            ai_explanation=ai_explanation,
            recommendation=recommendation
        )

        return jsonify({
            "id": saved_id,
            "input_type": "url",
            "input_data": sanitized_url,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "indicators": indicator_dicts,
            "score_breakdown": score_breakdown,
            "url_analysis": url_dict,
            "ai_explanation": ai_explanation,
            "recommendation": recommendation,
            "ascii_report": ascii_report
        })

    except Exception as e:
        return jsonify({"error": f"URL analysis failed: {str(e)}"}), 500

@app.route('/api/history', methods=['GET'])
def history_endpoint():
    try:
        limit = min(int(request.args.get('limit', 50)), 100)
        offset = max(int(request.args.get('offset', 0)), 0)
        records = get_history(limit=limit, offset=offset)
        return jsonify(records)
    except Exception as e:
        return jsonify({"error": f"Failed to fetch history: {str(e)}"}), 500

@app.route('/api/history/<int:record_id>', methods=['GET'])
def history_detail_endpoint(record_id):
    try:
        record = get_analysis_by_id(record_id)
        if not record:
            return jsonify({"error": f"Record with ID {record_id} not found."}), 404
        return jsonify(record)
    except Exception as e:
        return jsonify({"error": f"Failed to retrieve record: {str(e)}"}), 500

@app.route('/api/history/<int:record_id>', methods=['DELETE'])
def history_delete_endpoint(record_id):
    try:
        deleted = delete_analysis(record_id)
        if not deleted:
            return jsonify({"error": f"Record with ID {record_id} not found."}), 404
        return jsonify({"success": True, "message": f"Record {record_id} deleted."})
    except Exception as e:
        return jsonify({"error": f"Failed to delete record: {str(e)}"}), 500

@app.route('/api/run-tests', methods=['POST'])
def run_tests_endpoint():
    """Execute Python unit test suite and return results."""
    try:
        result = subprocess.run(
            ['python3', '-m', 'unittest', 'discover', 'tests'],
            capture_output=True,
            text=True,
            timeout=15
        )
        return jsonify({
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.returncode
        })
    except Exception as e:
        return jsonify({"error": f"Failed to execute tests: {str(e)}"}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
