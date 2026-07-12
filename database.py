import sqlite3
import os
from datetime import datetime
from config import DATABASE_PATH

def get_db_connection():
    """Create and return a database connection, handling timeout for concurrent writes."""
    conn = sqlite3.connect(DATABASE_PATH, timeout=10.0)
    # Enable dict factory to easily read logs as dictionaries
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize SQLite database and create logs table if it doesn't exist."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            method TEXT NOT NULL,
            url TEXT NOT NULL,
            status TEXT NOT NULL,
            reason TEXT,
            payload TEXT,
            user_agent TEXT
        )
    """)
    conn.commit()
    conn.close()

def log_request(client_ip: str, method: str, url: str, status: str, reason: str = "", payload: str = "", user_agent: str = ""):
    """Insert a new request log into the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    timestamp = datetime.utcnow().isoformat()
    cursor.execute("""
        INSERT INTO logs (timestamp, client_ip, method, url, status, reason, payload, user_agent)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (timestamp, client_ip, method, url, status, reason, payload, user_agent))
    conn.commit()
    conn.close()

def get_logs(limit: int = 100, offset: int = 0, status_filter: str = None, reason_filter: str = None, search_query: str = None):
    """Retrieve logs with filtering, sorting from newest to oldest."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = "SELECT * FROM logs WHERE 1=1"
    params = []
    
    if status_filter:
        query += " AND status = ?"
        params.append(status_filter)
        
    if reason_filter:
        query += " AND reason = ?"
        params.append(reason_filter)
        
    if search_query:
        query += " AND (client_ip LIKE ? OR url LIKE ? OR payload LIKE ?)"
        like_pattern = f"%{search_query}%"
        params.extend([like_pattern, like_pattern, like_pattern])
        
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    
    # Convert Row objects to dictionaries
    logs = [dict(row) for row in rows]
    
    # Get total count for pagination
    count_query = "SELECT COUNT(*) FROM logs WHERE 1=1"
    count_params = []
    
    if status_filter:
        count_query += " AND status = ?"
        count_params.append(status_filter)
        
    if reason_filter:
        count_query += " AND reason = ?"
        count_params.append(reason_filter)
        
    if search_query:
        count_query += " AND (client_ip LIKE ? OR url LIKE ? OR payload LIKE ?)"
        count_params.extend([like_pattern, like_pattern, like_pattern])
        
    cursor.execute(count_query, count_params)
    total_count = cursor.fetchone()[0]
    
    conn.close()
    return logs, total_count

def get_stats():
    """Retrieve aggregated stats for dashboard cards and charts."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Basic counts
    cursor.execute("SELECT COUNT(*) FROM logs")
    total_requests = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM logs WHERE status = 'Blocked'")
    blocked_requests = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM logs WHERE status = 'Allowed'")
    allowed_requests = cursor.fetchone()[0]
    
    # Breakdown of attack categories
    cursor.execute("""
        SELECT reason, COUNT(*) as count 
        FROM logs 
        WHERE status = 'Blocked' 
        GROUP BY reason
    """)
    reason_rows = cursor.fetchall()
    reasons = {row['reason']: row['count'] for row in reason_rows}
    
    # Recent logs for dashboard preview
    cursor.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 5")
    recent_rows = cursor.fetchall()
    recent_logs = [dict(row) for row in recent_rows]
    
    conn.close()
    
    return {
        "total_requests": total_requests,
        "blocked_requests": blocked_requests,
        "allowed_requests": allowed_requests,
        "reasons": reasons,
        "recent_logs": recent_logs
    }
