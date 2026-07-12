import time
import os
from datetime import datetime
from collections import defaultdict
import uvicorn
from fastapi import FastAPI, Request, Response, Query
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

import config
import database
from models import LogEntry, WafStats
from waf.detector import inspect_request
from waf.logger import log_allowed_request, log_blocked_request
from waf.proxy import forward_request

app = FastAPI(title="WebGuard Reverse-Proxy Gateway")

# Setup templates and static directory
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# In-memory dictionary for sliding-window rate limiting
rate_limit_records = defaultdict(list)

def is_rate_limited(ip: str) -> bool:
    """
    Checks if a client IP has exceeded the rate limit configured in config.py.
    Uses an in-memory sliding window bucket.
    """
    now = time.time()
    window_start = now - config.RATE_LIMIT_PERIOD
    
    # Filter timestamps to keep only those within the current sliding window
    timestamps = [t for t in rate_limit_records[ip] if t > window_start]
    rate_limit_records[ip] = timestamps
    
    if len(timestamps) >= config.RATE_LIMIT_LIMIT:
        return True
        
    # Record current request timestamp
    rate_limit_records[ip].append(now)
    return False

@app.on_event("startup")
def startup_event():
    """Perform database table setup on startup."""
    database.init_db()
    # Create static directory if it doesn't exist
    if not os.path.exists("static"):
        os.makedirs("static")

# ==========================================
# WAF Dashboard Routes
# ==========================================

@app.get("/dashboard")
async def show_dashboard(request: Request):
    """Render the dashboard UI."""
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/logs")
async def show_logs(request: Request):
    """Render the detailed logs explorer UI."""
    return templates.TemplateResponse("logs.html", {"request": request})

@app.get("/api/stats")
async def get_dashboard_stats():
    """Retrieve WAF statistics JSON for chart rendering."""
    stats = database.get_stats()
    return stats

@app.get("/api/logs")
async def get_logs_api(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=20, ge=1, le=100),
    status: str = Query(default=None),
    reason: str = Query(default=None),
    search: str = Query(default=None)
):
    """Retrieve a paginated and filtered list of WAF logs."""
    offset = (page - 1) * size
    logs, total = database.get_logs(
        limit=size,
        offset=offset,
        status_filter=status,
        reason_filter=reason,
        search_query=search
    )
    return {
        "logs": logs,
        "total": total,
        "page": page,
        "size": size
    }

# ==========================================
# Catch-all Reverse-Proxy Route
# ==========================================

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def proxy_gateway(request: Request, path: str):
    """
    Catch-all route that intercepts all non-dashboard traffic.
    Passes requests through rate limiting and rule verification before proxying.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "")
    
    # Construct complete path with query params for database logging
    full_path = request.url.path
    if request.url.query:
        full_path += f"?{request.url.query}"

    # 1. Rate Limiting Check
    if is_rate_limited(client_ip):
        payload_desc = f"Rate limit exceeded: {config.RATE_LIMIT_LIMIT} reqs per {config.RATE_LIMIT_PERIOD} seconds."
        log_blocked_request(
            client_ip=client_ip,
            method=request.method,
            url=full_path,
            reason="Rate Limit",
            payload=payload_desc,
            user_agent=user_agent
        )
        return templates.TemplateResponse(
            "block.html",
            {
                "request": request,
                "reason": "Rate Limit Exceeded",
                "ip": client_ip,
                "path": request.url.path,
                "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
            },
            status_code=429
        )

    # 2. Security Threat Inspection (SQLi, XSS, Path Traversal)
    is_attack, category, matched_payload, body_bytes = await inspect_request(request)

    if is_attack:
        log_blocked_request(
            client_ip=client_ip,
            method=request.method,
            url=full_path,
            reason=category,
            payload=matched_payload,
            user_agent=user_agent
        )
        return templates.TemplateResponse(
            "block.html",
            {
                "request": request,
                "reason": f"{category} Injection Blocked",
                "ip": client_ip,
                "path": request.url.path,
                "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
            },
            status_code=403
        )

    # 3. Request is safe, log as allowed and forward to the target backend
    log_allowed_request(
        client_ip=client_ip,
        method=request.method,
        url=full_path,
        user_agent=user_agent
    )
    
    return await forward_request(request, body_bytes)

if __name__ == "__main__":
    uvicorn.run("app:app", host=config.WAF_HOST, port=config.WAF_PORT, reload=True)
