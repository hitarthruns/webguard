from database import log_request

def log_allowed_request(client_ip: str, method: str, url: str, user_agent: str):
    """Log an allowed clean request to the database."""
    log_request(
        client_ip=client_ip,
        method=method,
        url=url,
        status="Allowed",
        reason="N/A",
        payload="",
        user_agent=user_agent
    )

def log_blocked_request(client_ip: str, method: str, url: str, reason: str, payload: str, user_agent: str):
    """Log a blocked malicious request or rate-limited request to the database."""
    log_request(
        client_ip=client_ip,
        method=method,
        url=url,
        status="Blocked",
        reason=reason,
        payload=payload,
        user_agent=user_agent
    )
