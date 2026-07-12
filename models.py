from pydantic import BaseModel
from typing import Optional, List, Dict

class LogEntry(BaseModel):
    id: int
    timestamp: str
    client_ip: str
    method: str
    url: str
    status: str
    reason: Optional[str] = None
    payload: Optional[str] = None
    user_agent: Optional[str] = None

class WafStats(BaseModel):
    total_requests: int
    blocked_requests: int
    allowed_requests: int
    reasons: Dict[str, int]
    recent_logs: List[LogEntry]
