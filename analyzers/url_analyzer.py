"""
Dedicated URL Analyzer module.
Performs comprehensive static heuristics and structural analysis on URLs.
Strictly static: NEVER connects, requests, or executes external URLs.
"""
import re
import urllib.parse
from typing import List, Tuple, Optional
from models.analysis import Indicator, URLAnalysisResult

# Optional tldextract with graceful standard library fallback
try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False

IPV4_PATTERN = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)

SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'work', 'loan', 'click', 'fit',
    'support', 'country', 'stream', 'download', 'racing', 'win', 'vip', 'buzz'
}

LOGIN_KEYWORDS = ['login', 'signin', 'sign-in', 'log-in', 'logon', 'auth', 'oauth', 'session']
VERIFICATION_KEYWORDS = ['verify', 'verification', 'confirm', 'validate', 'authenticate', 'identity', 'reactivate', 'unlock']
ACCOUNT_KEYWORDS = ['account', 'security', 'secure', 'billing', 'wallet', 'profile', 'credential', 'password']
FINANCIAL_KEYWORDS = ['payment', 'banking', 'bank', 'creditcard', 'paypal', 'invoice', 'refund', 'wire']

KNOWN_TARGET_BRANDS = [
    'paypal', 'apple', 'microsoft', 'google', 'netflix', 'amazon', 'chase',
    'bankofamerica', 'wellsfargo', 'facebook', 'instagram', 'dhl', 'fedex', 'usps'
]

def parse_domain_parts(hostname: str) -> Tuple[List[str], str, str]:
    """
    Extract subdomains, registered domain, and suffix (TLD).
    Uses tldextract if installed, otherwise uses robust regex/split.
    """
    if not hostname:
        return [], "", ""

    # Strip port if present
    if ':' in hostname:
        hostname = hostname.split(':')[0]

    hostname = hostname.lower().strip()

    if HAS_TLDEXTRACT:
        extracted = tldextract.extract(hostname)
        subdomains = [s for s in extracted.subdomain.split('.') if s] if extracted.subdomain else []
        registered_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
        suffix = extracted.suffix
        return subdomains, registered_domain, suffix

    # Fallback parser for standard library
    parts = hostname.split('.')
    if len(parts) == 1:
        return [], parts[0], ""
    elif len(parts) == 2:
        return [], hostname, parts[1]
    
    # Handle known multi-part suffixes like .co.uk, .com.au, .gov.uk, etc.
    multi_suffixes = {'co.uk', 'com.au', 'co.nz', 'gov.uk', 'org.uk', 'com.br', 'co.jp', 'com.mx', 'ac.uk'}
    last_two = f"{parts[-2]}.{parts[-1]}"
    if last_two in multi_suffixes and len(parts) >= 3:
        suffix = last_two
        registered_domain = f"{parts[-3]}.{suffix}"
        subdomains = parts[:-3]
    else:
        suffix = parts[-1]
        registered_domain = f"{parts[-2]}.{suffix}"
        subdomains = parts[:-2]

    return subdomains, registered_domain, suffix

def analyze_url(url: str) -> URLAnalysisResult:
    """
    Perform deep static heuristics on a target URL.
    Returns URLAnalysisResult and generates explainable indicators.
    """
    if not url or not isinstance(url, str):
        url = ""

    url_clean = url.strip()
    if not url_clean.startswith(('http://', 'https://', 'ftp://')):
        # Prepend http:// for parsing if scheme was omitted
        parsed = urllib.parse.urlparse('http://' + url_clean)
        is_explicit_scheme = False
    else:
        parsed = urllib.parse.urlparse(url_clean)
        is_explicit_scheme = True

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path
    query = parsed.query
    hostname = parsed.hostname or (netloc.split(':')[0] if netloc else "")
    
    # Port detection
    port = parsed.port
    has_unusual_port = False
    if port and port not in (80, 443):
        has_unusual_port = True

    is_https = scheme == 'https'
    has_ip = bool(IPV4_PATTERN.match(hostname))
    
    subdomains, registered_domain, tld = parse_domain_parts(hostname)
    subdomain_count = len(subdomains)
    domain_length = len(hostname)
    path_length = len(path)
    
    # Parse query parameters count
    query_params = urllib.parse.parse_qs(query)
    query_params_count = len(query_params)
    
    # Hyphen & Dot counts
    hyphen_count = hostname.count('-')
    dot_count = hostname.count('.')
    has_excessive_hyphens = hyphen_count >= 2
    has_excessive_dots = dot_count >= 3
    
    # Suspicious character detection
    suspicious_chars = []
    if '@' in url_clean:
        suspicious_chars.append('@ character in authority (potential credential spoofing/redirect)')
    if '%' in url_clean:
        suspicious_chars.append('Percent-encoded / obfuscated characters detected')
    if '//' in path:
        suspicious_chars.append('Multiple consecutive slashes in URL path')
        
    has_suspicious_characters = len(suspicious_chars) > 0

    # Keyword matching
    combined_url_text = f"{hostname} {path} {query}".lower()
    matched_keywords = []
    
    found_login = [kw for kw in LOGIN_KEYWORDS if re.search(r'\b' + re.escape(kw) + r'\b', combined_url_text) or kw in hostname or kw in path]
    found_verify = [kw for kw in VERIFICATION_KEYWORDS if re.search(r'\b' + re.escape(kw) + r'\b', combined_url_text) or kw in hostname or kw in path]
    found_account = [kw for kw in ACCOUNT_KEYWORDS if re.search(r'\b' + re.escape(kw) + r'\b', combined_url_text) or kw in hostname or kw in path]
    found_finance = [kw for kw in FINANCIAL_KEYWORDS if re.search(r'\b' + re.escape(kw) + r'\b', combined_url_text) or kw in hostname or kw in path]
    
    matched_keywords.extend(found_login)
    matched_keywords.extend(found_verify)
    matched_keywords.extend(found_account)
    matched_keywords.extend(found_finance)
    matched_keywords = list(dict.fromkeys(matched_keywords))

    # Generate Explainable Indicators
    indicators: List[Indicator] = []

    # 1. IP Address Host
    if has_ip:
        indicators.append(Indicator(
            indicator="IP Address Used as Hostname",
            description="The URL uses a raw numeric IP address instead of a registered domain name, a hallmark of evasion and rogue hosting.",
            severity="critical",
            points=25,
            evidence=hostname,
            category="url_heuristic"
        ))

    # 2. Deceptive Subdomain / Excessive Subdomains
    if subdomain_count >= 3:
        indicators.append(Indicator(
            indicator="Excessive Subdomain Stacking",
            description="The URL uses an unusually deep subdomain chain to mask the actual root domain.",
            severity="medium",
            points=10,
            evidence=f"{'.'.join(subdomains)} ({subdomain_count} subdomains)",
            category="url_heuristic"
        ))

    # 3. Excessive Hyphens
    if has_excessive_hyphens:
        indicators.append(Indicator(
            indicator="Excessive Hyphens in Domain",
            description="Phishing actors frequently concatenate brand names and security words with multiple hyphens.",
            severity="medium",
            points=10,
            evidence=f"Hostname contains {hyphen_count} hyphens: '{hostname}'",
            category="url_heuristic"
        ))

    # 4. Login-related Path / Keywords
    if found_login:
        indicators.append(Indicator(
            indicator="Login/Authentication Keyword in URL",
            description="The URL targets authentication endpoints, frequently used in credential-harvesting attacks.",
            severity="medium",
            points=10,
            evidence=f"Matched login keywords: {', '.join(found_login)} in '{path or url_clean}'",
            category="url_heuristic"
        ))

    # 5. Account Verification Wording
    if found_verify:
        indicators.append(Indicator(
            indicator="Account Verification Keyword in URL",
            description="The URL contains verification or validation terms designed to deceive users into confirming credentials.",
            severity="high",
            points=12,
            evidence=f"Matched verification terms: {', '.join(found_verify)}",
            category="url_heuristic"
        ))

    # 6. Brand Impersonation in Non-Official Domain
    for brand in KNOWN_TARGET_BRANDS:
        if brand in hostname:
            # Check if root domain is actually that brand (e.g., paypal.com)
            if not (registered_domain.startswith(f"{brand}.") or registered_domain == brand):
                indicators.append(Indicator(
                    indicator="Brand Name in Subdomain / Impersonation",
                    description=f"The brand name '{brand}' appears inside a hostname whose base domain is '{registered_domain}'.",
                    severity="high",
                    points=20,
                    evidence=f"Brand '{brand}' found in deceptive host: {hostname}",
                    category="url_heuristic"
                ))
                break

    # 7. Suspicious Characters (@ or % hex encoding)
    if '@' in url_clean:
        indicators.append(Indicator(
            indicator="Deceptive Authority '@' Character",
            description="The '@' symbol in a URL causes browsers to treat preceding text as userinfo and navigate to the following host, hiding the real destination.",
            severity="critical",
            points=25,
            evidence=url_clean,
            category="url_heuristic"
        ))
    elif '%' in path or '%' in query:
        indicators.append(Indicator(
            indicator="Obfuscated Character Encoding",
            description="Hex/Percent encoding in the path or query can be employed to bypass simple pattern filters.",
            severity="low",
            points=8,
            evidence=f"Encoded sequences found in path: '{path}'",
            category="url_heuristic"
        ))

    # 8. Suspicious TLD
    if tld.lower() in SUSPICIOUS_TLDS:
        indicators.append(Indicator(
            indicator="High-Risk Free or Abused TLD",
            description=f"The top-level domain '.{tld}' is disproportionately associated with temporary phishing campaigns and spam.",
            severity="medium",
            points=10,
            evidence=f"TLD: .{tld}",
            category="url_heuristic"
        ))

    # 9. Non-Standard Port
    if has_unusual_port:
        indicators.append(Indicator(
            indicator="Non-Standard Web Port",
            description=f"The URL connects over port {port} instead of standard HTTP (80) or HTTPS (443), typical of ad-hoc or compromised servers.",
            severity="medium",
            points=12,
            evidence=f"Port: {port}",
            category="url_heuristic"
        ))

    # 10. Insecure Plain HTTP (if explicit)
    if is_explicit_scheme and not is_https and not has_ip:
        indicators.append(Indicator(
            indicator="Insecure Plaintext Protocol (HTTP)",
            description="The link transmits data unencrypted without TLS/HTTPS certificate protection.",
            severity="low",
            points=5,
            evidence=f"Scheme: {scheme}://",
            category="url_heuristic"
        ))

    # 11. Abnormally Long Domain or Path
    if domain_length > 35:
        indicators.append(Indicator(
            indicator="Abnormally Long Hostname",
            description=f"The hostname is {domain_length} characters long, often constructed to visually overflow address bars on mobile screens.",
            severity="low",
            points=6,
            evidence=f"Length: {domain_length} chars ({hostname})",
            category="url_heuristic"
        ))

    return URLAnalysisResult(
        url=url_clean,
        scheme=scheme if is_explicit_scheme else "none",
        is_https=is_https,
        domain=hostname,
        subdomains=subdomains,
        subdomain_count=subdomain_count,
        domain_length=domain_length,
        tld=tld,
        path=path,
        path_length=path_length,
        query_params_count=query_params_count,
        has_ip_address=has_ip,
        has_suspicious_characters=has_suspicious_characters,
        suspicious_character_details=suspicious_chars,
        hyphen_count=hyphen_count,
        dot_count=dot_count,
        has_excessive_hyphens=has_excessive_hyphens,
        has_excessive_dots=has_excessive_dots,
        has_unusual_port=has_unusual_port,
        port=port,
        matched_keywords=matched_keywords,
        indicators=indicators
    )
