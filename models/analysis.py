"""
Data models and structures for Phishing Investigation Lab.
"""
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional

@dataclass
class Indicator:
    indicator: str
    description: str
    severity: str  # "low", "medium", "high", "critical"
    points: int
    evidence: str
    category: str = "general"  # "urgency", "threat", "credential", "financial", "cta", "url_heuristic"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class URLAnalysisResult:
    url: str
    scheme: str
    is_https: bool
    domain: str
    subdomains: List[str] = field(default_factory=list)
    subdomain_count: int = 0
    domain_length: int = 0
    tld: str = ""
    path: str = ""
    path_length: int = 0
    query_params_count: int = 0
    has_ip_address: bool = False
    has_suspicious_characters: bool = False
    suspicious_character_details: List[str] = field(default_factory=list)
    hyphen_count: int = 0
    dot_count: int = 0
    has_excessive_hyphens: bool = False
    has_excessive_dots: bool = False
    has_unusual_port: bool = False
    port: Optional[int] = None
    matched_keywords: List[str] = field(default_factory=list)
    indicators: List[Indicator] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res['indicators'] = [ind.to_dict() if isinstance(ind, Indicator) else ind for ind in self.indicators]
        return res

@dataclass
class AnalysisResult:
    input_type: str  # "email" or "url"
    input_data: str
    risk_score: int
    risk_level: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    indicators: List[Indicator]
    score_breakdown: List[Dict[str, Any]]
    url_analysis: Optional[URLAnalysisResult] = None
    ai_explanation: Dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    id: Optional[int] = None
    created_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "input_type": self.input_type,
            "input_data": self.input_data,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "indicators": [ind.to_dict() if isinstance(ind, Indicator) else ind for ind in self.indicators],
            "score_breakdown": self.score_breakdown,
            "url_analysis": self.url_analysis.to_dict() if self.url_analysis else None,
            "ai_explanation": self.ai_explanation,
            "recommendation": self.recommendation,
            "created_at": self.created_at,
        }
