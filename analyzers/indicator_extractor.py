"""
Indicator Extractor module.
Statically parses emails and text to extract indicators, links, headers, and key phrases.
No network requests or execution are ever performed.
"""
import re
from typing import List, Dict, Any, Optional

URL_REGEX = re.compile(
    r'(?:https?|hxxps?|ftp)://[^\s<>"\'`()]+|www\.[^\s<>"\'`()]+',
    re.IGNORECASE
)

MAX_INPUT_LENGTH = 50000  # Enforce reasonable input bound for safety

def sanitize_input(text: str) -> str:
    """Sanitize and constrain input text."""
    if not text:
        return ""
    if len(text) > MAX_INPUT_LENGTH:
        return text[:MAX_INPUT_LENGTH]
    return text

def extract_urls(text: str) -> List[str]:
    """
    Extract all URLs from plain text or email bodies.
    Normalizes 'hxxp' to 'http' safely for static analysis.
    """
    if not text:
        return []
    
    clean_text = sanitize_input(text)
    raw_urls = URL_REGEX.findall(clean_text)
    
    normalized_urls = []
    seen = set()
    for raw in raw_urls:
        # Strip trailing punctuation commonly caught at end of sentences
        url = re.sub(r'[\.,;:\)\]>]+$', '', raw.strip())
        if url.startswith('hxxps://'):
            url = 'https://' + url[8:]
        elif url.startswith('hxxp://'):
            url = 'http://' + url[7:]
        elif url.startswith('www.'):
            url = 'http://' + url
            
        if url and url not in seen:
            seen.add(url)
            normalized_urls.append(url)
            
    return normalized_urls

def extract_email_headers(text: str) -> Dict[str, Optional[str]]:
    """
    Extract standard email header fields (Subject, From, To, Reply-To, Date) if present.
    """
    headers = {
        "subject": None,
        "from": None,
        "to": None,
        "reply_to": None,
        "date": None,
    }
    
    if not text:
        return headers
        
    lines = text.splitlines()
    for line in lines[:25]:  # Look in the initial header block
        line_clean = line.strip()
        if re.match(r'^Subject:\s*', line_clean, re.IGNORECASE):
            headers["subject"] = re.sub(r'^Subject:\s*', '', line_clean, flags=re.IGNORECASE)
        elif re.match(r'^From:\s*', line_clean, re.IGNORECASE):
            headers["from"] = re.sub(r'^From:\s*', '', line_clean, flags=re.IGNORECASE)
        elif re.match(r'^To:\s*', line_clean, re.IGNORECASE):
            headers["to"] = re.sub(r'^To:\s*', '', line_clean, flags=re.IGNORECASE)
        elif re.match(r'^Reply-To:\s*', line_clean, re.IGNORECASE):
            headers["reply_to"] = re.sub(r'^Reply-To:\s*', '', line_clean, flags=re.IGNORECASE)
        elif re.match(r'^Date:\s*', line_clean, re.IGNORECASE):
            headers["date"] = re.sub(r'^Date:\s*', '', line_clean, flags=re.IGNORECASE)
            
    return headers
