"""
Explainable Risk Scoring module.
Calculates transparent risk score, point breakdown, and human-readable analysis reports.
Strictly explainable: No black box numbers.
"""
from typing import List, Dict, Any, Tuple
from models.analysis import Indicator

def calculate_risk_score(indicators: List[Indicator]) -> Tuple[int, str, List[Dict[str, Any]]]:
    """
    Sum points from detected indicators and cap at 100.
    Returns (capped_score, risk_level, score_breakdown).
    """
    total_raw_points = sum(ind.points for ind in indicators)
    capped_score = min(100, max(0, total_raw_points))
    
    # Classify Risk Level according to specification:
    # 0–24: LOW
    # 25–49: MEDIUM
    # 50–74: HIGH
    # 75–100: CRITICAL
    if capped_score <= 24:
        risk_level = "LOW"
    elif capped_score <= 49:
        risk_level = "MEDIUM"
    elif capped_score <= 74:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    # Construct transparent breakdown list
    score_breakdown = []
    for ind in indicators:
        score_breakdown.append({
            "indicator": ind.indicator,
            "category": ind.category,
            "severity": ind.severity,
            "points": ind.points,
            "evidence": ind.evidence
        })

    return capped_score, risk_level, score_breakdown

def generate_recommendation(risk_level: str, indicators: List[Indicator]) -> str:
    """
    Produce actionable, safety-first recommendations tailored to risk level and detected tactics.
    """
    categories = {ind.category for ind in indicators}
    
    if risk_level in ("HIGH", "CRITICAL"):
        rec_parts = [
            "DO NOT click any embedded links or enter credentials.",
            "Verify this communication out-of-band using official verified phone numbers or direct bookmarks."
        ]
        if "credential" in categories:
            rec_parts.append("If credentials were submitted, immediately change passwords and revoke active sessions.")
        if "financial" in categories:
            rec_parts.append("Alert your finance department / banking institution to monitor unauthorized transactions.")
        rec_parts.append("Report this message to your internal Security Operations Center (SOC) or IT helpdesk.")
        return " ".join(rec_parts)
    elif risk_level == "MEDIUM":
        return ("Exercise caution. The message exhibits indicators often associated with phishing lures. "
                "Inspect sender domain headers and confirm requests via independent channels before interacting.")
    else:
        return ("Low risk detected. No strong phishing markers were identified. "
                "Always remain vigilant and adhere to company security verification policies.")

def generate_text_report(
    input_type: str,
    input_data: str,
    risk_score: int,
    risk_level: str,
    indicators: List[Indicator],
    recommendation: str,
    ai_summary: str = ""
) -> str:
    """
    Format a clean ASCII Phishing Analysis Report matching the specification.
    """
    sep = "━" * 50
    lines = [
        sep,
        "PHISHING ANALYSIS REPORT",
        f"Input Type: {input_type.upper()}",
        f"Risk Level: {risk_level}",
        f"Risk Score: {risk_score}/100",
        sep,
        "INDICATORS DETECTED"
    ]

    if not indicators:
        lines.append("✓ No suspicious indicators detected (Safe baseline)")
    else:
        for ind in indicators:
            lines.append(f"✓ {ind.indicator} (+{ind.points} pts) [{ind.severity.upper()}]")

    lines.append(sep)
    lines.append("EVIDENCE BREAKDOWN")
    
    if not indicators:
        lines.append("None")
    else:
        for ind in indicators:
            lines.append(f"\n[{ind.indicator}]")
            lines.append(f"Evidence: {ind.evidence}")
            lines.append(f"Why flagged: {ind.description}")

    lines.append("\n" + sep)
    lines.append("WHY THIS IS SUSPICIOUS")
    if ai_summary:
        lines.append(ai_summary)
    else:
        if risk_score >= 50:
            lines.append(
                "The analysis identified multiple coordinated deception vectors (urgency, threats, or deceptive links) "
                "designed to induce emotional compliance and bypass critical evaluation."
            )
        elif risk_score >= 25:
            lines.append(
                "Isolated warning indicators were detected. While not definitively malicious, these characteristics "
                "deviate from best-practice security communications."
            )
        else:
            lines.append("No active malicious intent or manipulation patterns were identified.")

    lines.append(sep)
    lines.append("RECOMMENDATION")
    lines.append(recommendation)
    lines.append(sep)

    return "\n".join(lines)
