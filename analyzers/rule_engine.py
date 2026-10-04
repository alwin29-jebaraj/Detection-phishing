"""
Rule-Based Phishing Detection Engine.
Deterministic rule checks for email text and message bodies.
Extracts explainable indicators with exact contextual evidence snippets.
"""
import re
from typing import List, Tuple, Optional
from models.analysis import Indicator
from analyzers.indicator_extractor import extract_urls, extract_email_headers
from analyzers.url_analyzer import analyze_url

# Compiled regex patterns with capturing / matching groups for exact evidence extraction

URGENCY_PATTERNS = [
    (re.compile(r'\b(urgent|urgently)\b', re.IGNORECASE), "Urgent language", 12, "medium",
     "The message relies on urgency markers to panic the recipient into acting without thinking."),
    (re.compile(r'\b(immediately|right now|act now|take action now|at once)\b', re.IGNORECASE), "Immediate action demand", 12, "medium",
     "Demands immediate action to bypass recipient deliberation."),
    (re.compile(r'\bwithin\s+(?:\d+|twenty[- ]four|forty[- ]eight|twelve)\s*(?:hours?|hrs?|minutes?|days?)\b', re.IGNORECASE), "Artificial deadline / countdown", 12, "medium",
     "Imposes an artificial ticking deadline or countdown to manufacture psychological pressure."),
    (re.compile(r'\b(today|expires today|valid until today|last chance|final notice)\b', re.IGNORECASE), "Impending expiration notice", 10, "medium",
     "Pressures the recipient with an impending expiration or final warning.")
]

THREAT_PATTERNS = [
    (re.compile(r'\b(?:your\s+)?account\s+(?:will\s+be\s+)?suspended\b', re.IGNORECASE), "Account suspension warning", 15, "high",
     "Threatens account suspension to provoke an emotional, fear-driven response."),
    (re.compile(r'\bpermanent(?:ly)?\s+suspension\b', re.IGNORECASE), "Threat of permanent suspension", 15, "high",
     "Threatens permanent revocation of services if immediate action is not taken."),
    (re.compile(r'\b(?:account\s+)?(?:blocked|locked|disabled|terminated|closed|restricted)\b', re.IGNORECASE), "Account restriction / lockout threat", 14, "high",
     "Claims access to services has been or will be restricted."),
    (re.compile(r'\bunusual\s+activity\b', re.IGNORECASE), "Unusual activity alert", 12, "medium",
     "Fabricates a security incident or unusual activity alert to create concern."),
    (re.compile(r'\b(?:unfamiliar\s+device|unrecognized\s+login|suspicious\s+login|review\s+(?:your\s+)?(?:account\s+)?activity)\b', re.IGNORECASE), "Suspicious login / Activity review alert", 12, "medium",
     "Alerts the recipient to purported unfamiliar devices or logins requiring account review."),
    (re.compile(r'\b(?:security\s+violation|unauthorized\s+access|security\s+breach)\b', re.IGNORECASE), "Security violation claim", 15, "high",
     "Claims a severe security violation has occurred."),
    (re.compile(r'\b(?:legal\s+action|law\s+enforcement|subpoena|police)\b', re.IGNORECASE), "Legal coercion threat", 18, "high",
     "Uses intimidation involving legal consequences or police action."),
    (re.compile(r'\bfailure\s+to\s+(?:verify|confirm|respond|act)\s+will\s+result\b', re.IGNORECASE), "Conditional punitive threat", 15, "high",
     "Constructs an explicit ultimatum tying inaction to punitive outcomes.")
]

CREDENTIAL_PATTERNS = [
    (re.compile(r'\b(?:verify|confirm|re-?authenticate|reactivate)\s+(?:your\s+)?account\b', re.IGNORECASE), "Account verification request", 20, "high",
     "Directs the user to re-verify or authenticate account credentials."),
    (re.compile(r'\b(?:enter|provide|confirm|update|submit)\s+(?:your\s+)?(?:password|passcode|pin|credentials)\b', re.IGNORECASE), "Credential harvesting prompt", 20, "critical",
     "Explicitly requests submission of secret credentials or passwords."),
    (re.compile(r'\b(?:login|log\s+in|sign\s+in)\s+(?:to\s+(?:your\s+)?(?:account|portal)|immediately|now)\b', re.IGNORECASE), "Login / sign-in solicitation", 15, "high",
     "Prompts the recipient to sign in through an unsolicited or untrusted channel."),
    (re.compile(r'\b(?:username\s+and\s+password|login\s+details|login\s+credentials)\b', re.IGNORECASE), "Login credentials solicitation", 18, "high",
     "References username, password, or security credentials directly.")
]

FINANCIAL_PATTERNS = [
    (re.compile(r'\b(?:bank\s+account|routing\s+number|wire\s+transfer)\b', re.IGNORECASE), "Bank account / Wire transfer request", 15, "high",
     "References direct banking details or wire transfer mechanisms."),
    (re.compile(r'\b(?:credit\s+card|debit\s+card|cvv|security\s+code|expiration\s+date)\b', re.IGNORECASE), "Payment card details solicitation", 18, "critical",
     "Prompts for payment card numbers, CVV codes, or card expiration dates."),
    (re.compile(r'\b(?:unclaimed\s+refund|overdue\s+invoice|pending\s+transaction|payment\s+declined)\b', re.IGNORECASE), "Transaction / Refund lure", 14, "medium",
     "Uses financial lures such as bogus invoices, declined charges, or unclaimed refunds."),
    (re.compile(r'\b(?:crypto(?:currency)?|bitcoin|wallet\s+phrase|seed\s+phrase|private\s+key)\b', re.IGNORECASE), "Cryptocurrency / Seed phrase request", 20, "critical",
     "Solicits private keys, recovery seed phrases, or cryptocurrency transfers.")
]

CTA_PATTERNS = [
    (re.compile(r'\b(?:click\s+here|follow\s+this\s+link|use\s+the\s+link\s+below)\b', re.IGNORECASE), "Generic click lure", 10, "medium",
     "Directs the user to an opaque link rather than an official site or bookmark."),
    (re.compile(r'\b(?:verify\s+now|confirm\s+now|validate\s+now|secure\s+now)\b', re.IGNORECASE), "Immediate verification CTA", 12, "medium",
     "Call-to-action urging instant confirmation."),
    (re.compile(r'\b(?:update\s+your\s+(?:information|details|billing|profile))\b', re.IGNORECASE), "Information update CTA", 10, "medium",
     "Requests unsolicited update of personal or financial information.")
]

def find_evidence_snippet(text: str, match_span: Tuple[int, int], window: int = 50) -> str:
    """
    Extract a clean sentence or sentence fragment around the matched span.
    """
    start, end = match_span
    context_start = max(0, start - window)
    context_end = min(len(text), end + window)
    
    # Try expanding to sentence boundaries if nearby
    snippet = text[context_start:context_end].strip()
    # Normalize excessive newlines
    snippet = re.sub(r'\s+', ' ', snippet)
    
    # Prefix/suffix ellipses if truncated
    if context_start > 0 and not snippet.startswith('...'):
        snippet = '...' + snippet
    if context_end < len(text) and not snippet.endswith('...'):
        snippet = snippet + '...'
        
    return snippet

def run_email_rules(email_text: str) -> Tuple[List[Indicator], List[str]]:
    """
    Run deterministic rule detection over email text.
    Returns (detected_indicators, extracted_urls).
    """
    if not email_text:
        return [], []

    indicators: List[Indicator] = []
    seen_indicator_names = set()

    def check_pattern_family(patterns, category: str):
        for pattern, name, points, severity, desc in patterns:
            match = pattern.search(email_text)
            if match and name not in seen_indicator_names:
                seen_indicator_names.add(name)
                # Extract clean evidence
                snippet = find_evidence_snippet(email_text, match.span(), window=35)
                # Also highlight the exact matched phrase
                exact_matched = match.group(0)
                evidence = f"\"{exact_matched}\" in: {snippet}"
                
                indicators.append(Indicator(
                    indicator=name,
                    description=desc,
                    severity=severity,
                    points=points,
                    evidence=evidence,
                    category=category
                ))

    # Check text categories
    check_pattern_family(URGENCY_PATTERNS, "urgency")
    check_pattern_family(THREAT_PATTERNS, "threat")
    check_pattern_family(CREDENTIAL_PATTERNS, "credential")
    check_pattern_family(FINANCIAL_PATTERNS, "financial")
    check_pattern_family(CTA_PATTERNS, "cta")

    # Check email headers if present
    headers = extract_email_headers(email_text)
    if headers.get('subject'):
        sub = headers['subject']
        if re.search(r'\b(urgent|action required|suspended|critical|alert|final notice)\b', sub, re.IGNORECASE):
            if "High-Pressure Subject Line" not in seen_indicator_names:
                seen_indicator_names.add("High-Pressure Subject Line")
                indicators.append(Indicator(
                    indicator="High-Pressure Subject Line",
                    description="The subject line utilizes urgent or threatening wording to prompt unconsidered email opens.",
                    severity="medium",
                    points=10,
                    evidence=f"Subject: {sub}",
                    category="urgency"
                ))

    # Extract and analyze URLs found in email
    urls = extract_urls(email_text)
    for u in urls:
        url_res = analyze_url(u)
        for url_ind in url_res.indicators:
            # Avoid duplicate indicators if multiple identical findings
            dedup_key = f"{url_ind.indicator}_{url_ind.evidence}"
            if dedup_key not in seen_indicator_names:
                seen_indicator_names.add(dedup_key)
                indicators.append(url_ind)

    return indicators, urls
