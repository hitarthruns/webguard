import os

# WAF Server Settings
WAF_HOST = os.getenv("WAF_HOST", "127.0.0.1")
WAF_PORT = int(os.getenv("WAF_PORT", 8081))

# Target Backend Server Settings (The web app we are protecting)
BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000")

# SQLite Database Settings
DATABASE_PATH = os.getenv("DATABASE_PATH", "attacks.db")

# Rate Limiting Settings
# Allow 60 requests per minute per IP address
RATE_LIMIT_LIMIT = int(os.getenv("RATE_LIMIT_LIMIT", 60))
RATE_LIMIT_PERIOD = int(os.getenv("RATE_LIMIT_PERIOD", 60))

# WAF Security Rule Controls
RULES_ENABLED = {
    "SQLi": True,
    "XSS": True,
    "Traversal": True
}
