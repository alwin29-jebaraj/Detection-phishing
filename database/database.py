"""
SQLite Database module for Phishing Investigation Lab.
Stores analysis history and provides retrieval and metric aggregations.
Never collects or stores passwords, tokens, or credentials.
"""
import sqlite3
import json
import os
from typing import List, Dict, Any, Optional

DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'phishing_lab.db')

def get_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path: str = DEFAULT_DB_PATH):
    """Initialize SQLite database tables."""
    conn = get_connection(db_path)
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                input_type TEXT NOT NULL,
                input_data TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                indicators_json TEXT NOT NULL,
                score_breakdown_json TEXT NOT NULL,
                url_analysis_json TEXT,
                ai_explanation_json TEXT,
                recommendation TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_analyses_created_at ON analyses(created_at DESC)")
    conn.close()

def save_analysis(
    input_type: str,
    input_data: str,
    risk_score: int,
    risk_level: str,
    indicators: List[Dict[str, Any]],
    score_breakdown: List[Dict[str, Any]],
    url_analysis: Optional[Dict[str, Any]] = None,
    ai_explanation: Optional[Dict[str, Any]] = None,
    recommendation: str = "",
    db_path: str = DEFAULT_DB_PATH
) -> int:
    """Save an analysis record and return its generated ID."""
    init_db(db_path)
    conn = get_connection(db_path)
    with conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO analyses (
                input_type, input_data, risk_score, risk_level,
                indicators_json, score_breakdown_json, url_analysis_json,
                ai_explanation_json, recommendation
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            input_type,
            input_data[:2000],  # Keep preview length safe
            risk_score,
            risk_level,
            json.dumps(indicators),
            json.dumps(score_breakdown),
            json.dumps(url_analysis) if url_analysis else None,
            json.dumps(ai_explanation) if ai_explanation else None,
            recommendation
        ))
        inserted_id = cur.lastrowid
    conn.close()
    return inserted_id

def get_history(limit: int = 50, offset: int = 0, db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """Retrieve history of previous analyses."""
    init_db(db_path)
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        SELECT id, input_type, input_data, risk_score, risk_level,
               indicators_json, score_breakdown_json, url_analysis_json,
               ai_explanation_json, recommendation, created_at
        FROM analyses
        ORDER BY id DESC
        LIMIT ? OFFSET ?
    """, (limit, offset))
    rows = cur.fetchall()
    conn.close()
    
    results = []
    for r in rows:
        results.append({
            "id": r["id"],
            "input_type": r["input_type"],
            "input_data": r["input_data"],
            "risk_score": r["risk_score"],
            "risk_level": r["risk_level"],
            "indicators": json.loads(r["indicators_json"]) if r["indicators_json"] else [],
            "score_breakdown": json.loads(r["score_breakdown_json"]) if r["score_breakdown_json"] else [],
            "url_analysis": json.loads(r["url_analysis_json"]) if r["url_analysis_json"] else None,
            "ai_explanation": json.loads(r["ai_explanation_json"]) if r["ai_explanation_json"] else {},
            "recommendation": r["recommendation"],
            "created_at": r["created_at"],
        })
    return results

def get_analysis_by_id(analysis_id: int, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    """Retrieve a single detailed analysis report by ID."""
    init_db(db_path)
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        SELECT id, input_type, input_data, risk_score, risk_level,
               indicators_json, score_breakdown_json, url_analysis_json,
               ai_explanation_json, recommendation, created_at
        FROM analyses
        WHERE id = ?
    """, (analysis_id,))
    row = cur.fetchone()
    conn.close()
    
    if not row:
        return None
        
    return {
        "id": row["id"],
        "input_type": row["input_type"],
        "input_data": row["input_data"],
        "risk_score": row["risk_score"],
        "risk_level": row["risk_level"],
        "indicators": json.loads(row["indicators_json"]) if row["indicators_json"] else [],
        "score_breakdown": json.loads(row["score_breakdown_json"]) if row["score_breakdown_json"] else [],
        "url_analysis": json.loads(row["url_analysis_json"]) if row["url_analysis_json"] else None,
        "ai_explanation": json.loads(row["ai_explanation_json"]) if row["ai_explanation_json"] else {},
        "recommendation": row["recommendation"],
        "created_at": row["created_at"],
    }

def delete_analysis(analysis_id: int, db_path: str = DEFAULT_DB_PATH) -> bool:
    """Delete an analysis record from history."""
    init_db(db_path)
    conn = get_connection(db_path)
    with conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))
        deleted = cur.rowcount > 0
    conn.close()
    return deleted

def get_stats(db_path: str = DEFAULT_DB_PATH) -> Dict[str, Any]:
    """Retrieve aggregated dashboard metrics."""
    init_db(db_path)
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN risk_level IN ('CRITICAL', 'HIGH') THEN 1 ELSE 0 END) as high_risk,
            SUM(CASE WHEN risk_level = 'MEDIUM' THEN 1 ELSE 0 END) as medium_risk,
            SUM(CASE WHEN risk_level = 'LOW' THEN 1 ELSE 0 END) as low_risk,
            AVG(risk_score) as avg_score
        FROM analyses
    """)
    row = cur.fetchone()
    conn.close()
    
    return {
        "total": row["total"] or 0,
        "high_risk": row["high_risk"] or 0,
        "medium_risk": row["medium_risk"] or 0,
        "low_risk": row["low_risk"] or 0,
        "avg_score": round(row["avg_score"] or 0, 1)
    }
