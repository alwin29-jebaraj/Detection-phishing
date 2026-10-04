"""
AI/NLP Explanation Service.
Takes structured rule findings, URL heuristics, and risk score.
Synthesizes natural language explanations without overriding the deterministic rule engine.
Gracefully falls back to deterministic rule synthesis when AI API is unavailable.
"""
import os
import json
from typing import Dict, Any, List

def build_deterministic_explanation(
    text: str,
    rule_indicators: List[Dict[str, Any]],
    url_analysis: Dict[str, Any],
    risk_score: int,
    risk_level: str
) -> Dict[str, Any]:
    """
    Generate a deterministic, structured natural-language explanation
    when the AI API is offline or unconfigured.
    """
    if not rule_indicators:
        return {
            "short_explanation": "No suspicious phishing indicators or deceptive patterns were detected during this evaluation.",
            "main_suspicious_behavior": "Benign communication baseline; normal informational message.",
            "most_important_indicators": ["No high-urgency triggers", "No credential requests", "No deceptive links"],
            "recommended_action": "Standard operating procedure: Keep software updated and follow routine security hygiene.",
            "provider": "Rule-Based Deterministic Engine (Offline Fallback)"
        }

    indicator_names = [ind.get("indicator") for ind in rule_indicators if ind.get("indicator")]
    high_sev = [ind for ind in rule_indicators if ind.get("severity") in ("high", "critical")]
    
    # Synthesize behavior description
    behaviors = []
    if any(ind.get("category") == "urgency" for ind in rule_indicators):
        behaviors.append("manufactured urgency")
    if any(ind.get("category") == "threat" for ind in rule_indicators):
        behaviors.append("punitive threats (account suspension/closure)")
    if any(ind.get("category") == "credential" for ind in rule_indicators):
        behaviors.append("unsolicited credential verification demands")
    if any(ind.get("category") == "financial" for ind in rule_indicators):
        behaviors.append("financial / transaction lures")
    if any(ind.get("category") == "url_heuristic" for ind in rule_indicators):
        behaviors.append("suspicious URL domain patterns")

    behavior_summary = " + ".join(behaviors) if behaviors else "suspicious communication patterns"
    
    short_explanation = (
        f"This item was classified as {risk_level} ({risk_score}/100) because it exhibits "
        f"{behavior_summary}. Attackers use these psychological triggers to bypass critical judgment "
        f"and direct targets toward credential-harvesting mechanisms."
    )

    top_indicators = [
        f"{ind.get('indicator')} (+{ind.get('points')} pts): {ind.get('description')}"
        for ind in (high_sev[:3] or rule_indicators[:3])
    ]

    action = (
        "Do not click any embedded links or provide login credentials. "
        "Verify account security directly through an official browser bookmark or the organization's verified app."
        if risk_score >= 50 else
        "Inspect sender addresses carefully and verify any unexpected requests out-of-band."
    )

    return {
        "short_explanation": short_explanation,
        "main_suspicious_behavior": f"Coordinated combination of: {', '.join(indicator_names[:4])}",
        "most_important_indicators": top_indicators,
        "recommended_action": action,
        "provider": "Rule-Based Deterministic NLP Synthesizer (AI Baseline)"
    }

def generate_ai_explanation(
    text: str,
    rule_indicators: List[Dict[str, Any]],
    url_analysis: Dict[str, Any],
    risk_score: int,
    risk_level: str
) -> Dict[str, Any]:
    """
    Main entry point for AI explanation.
    Tries Gemini API if available, otherwise falls back to deterministic synthesis.
    """
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return build_deterministic_explanation(text, rule_indicators, url_analysis, risk_score, risk_level)

    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=api_key)
        
        prompt = f"""
You are an expert Cybersecurity Incident Response & Threat Analyst.
Analyze the following structured phishing detection results and provide an explainable summary.

CONTEXT DATA:
- Input Risk Score: {risk_score}/100
- Risk Level: {risk_level}
- Detected Rule Indicators: {json.dumps(rule_indicators, indent=2)}
- URL Analysis Heuristics: {json.dumps(url_analysis, indent=2)}
- Analyzed Raw Snippet: {text[:500]}

IMPORTANT GUIDELINES:
1. Do NOT recalculate or override the deterministic risk score ({risk_score}/100).
2. Clearly explain WHY these indicators together represent a threat or safe baseline.
3. Be professional, concise, and educational for a SOC trainee or employee.

Respond ONLY with a valid JSON object matching this schema:
{{
  "short_explanation": "Concise 2-3 sentence overview explaining why it was classified as this risk level.",
  "main_suspicious_behavior": "Key psychological or technical deception vector (e.g. Manufactured Urgency + Account Suspension Ultimatum)",
  "most_important_indicators": [
    "Indicator 1 summary",
    "Indicator 2 summary",
    "Indicator 3 summary"
  ],
  "recommended_action": "Clear, practical instructions on what the recipient should do right now."
}}
"""
        response = client.models.generate_content(
            model='gemini-3.8-flash',
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                temperature=0.2
            )
        )
        
        if response and response.text:
            parsed = json.loads(response.text)
            parsed["provider"] = "Gemini 3.8 Flash (AI Analyst)"
            return parsed
            
    except Exception as e:
        # Graceful fallback: Never crash the application if AI network/call fails
        pass

    fallback = build_deterministic_explanation(text, rule_indicators, url_analysis, risk_score, risk_level)
    return fallback
