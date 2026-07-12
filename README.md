# 🛡️ WebGuard

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/framework-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://opensource.org/licenses/MIT)

**WebGuard** is a high-performance, lightweight reverse-proxy Web Application Firewall (WAF) designed to safeguard web applications from malicious traffic. Positioned directly in front of your backend servers, WebGuard intercepts, decodes, and inspects incoming HTTP requests in real time to filter out common web application vulnerabilities (such as SQL Injection, Cross-Site Scripting, and Path Traversal) and enforce rate limits, before forwarding safe traffic to your application. It features a stunning, real-time dark-themed monitoring dashboard for instant security visibility.

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#%EF%B8%8F-architecture)
- [Technologies Used](#-technologies-used)
- [Prerequisites](#-prerequisites)
- [Installation Guide](#-installation-guide)
- [Usage Instructions](#-usage-instructions)
- [Project Structure](#-project-structure)
- [Testing & Validation](#-testing--validation)
- [Security Rule Configurations](#-security-rule-configurations)

---

## ✨ Features

- **Deep Packet Inspection (DPI)**: Decodes and normalizes incoming URLs, paths, query inputs, headers, and request bodies (using URL decoding) to inspect for malicious signatures.
- **Pre-Compiled Regex Rulesets**: Targets common injection attacks:
  - **SQL Injection (SQLi)**: Detects payloads like `UNION SELECT`, `OR 1=1`, time delays (`pg_sleep`, `dbms_pipe.receive_message`), etc.
  - **Cross-Site Scripting (XSS)**: Filters out `<script>`, `onerror`, `onload`, and javascript protocol injections.
  - **Path Traversal**: Flags directory traversal patterns (e.g., `../`, `/etc/passwd`, `win.ini`).
- **Sliding-Window Rate Limiting**: Employs an in-memory rate-limiter per client IP address to prevent Denial of Service (DoS) and brute-force attacks.
- **Glassmorphism Monitoring Dashboard**: A modern, responsive dark-mode dashboard (built with Tailwind CSS and Chart.js) featuring:
  - Real-time threat detection metrics via background polling.
  - Interactive charts displaying allowed vs. blocked traffic trends.
  - Detailed Logs Explorer with filterable and searchable threat categories, pagination, and request payload inspection.
- **Custom Block Page**: A clean, branded 403 Forbidden screen displaying transparent details of the security violation, timestamp, and block reason for blocked clients.

---

## 🛡️ Architecture

WebGuard acts as a reverse proxy, standing between the client and your backend application:

```mermaid
graph TD
    Client[🌐 Client] -->|HTTP Request| WG[🛡️ WebGuard Proxy: Port 8081]
    
    subgraph Inspection Engine
        WG --> RateLimit{Rate Limiter}
        RateLimit -->|Pass| Decoder[URL Decoder / Normalizer]
        RateLimit -->|Exceeded (429)| BlockPage[❌ Block Screen]
        
        Decoder --> Detector{Security Detector}
        Detector -->|Attack Detected (403)| BlockPage
        Detector -->|Clean Request| ProxyClient[Proxy Forwarder]
    end
    
    subgraph Logging
        BlockPage --> DB[(SQLite: attacks.db)]
        ProxyClient --> DB
    end

    ProxyClient -->|Forward Request| Backend[🖥️ Target Backend: Port 8000]
    Backend -->|Response| ProxyClient
    ProxyClient -->|Return Response| Client
```

---

## 🛠️ Technologies Used

WebGuard leverages a modern and robust stack of backend frameworks and frontend visualization libraries:

- **Programming Language**: Python 3.8+
- **Core Framework**: [FastAPI](https://fastapi.tiangolo.com/) – A modern, fast (high-performance), web framework for building APIs.
- **ASGI Server**: [Uvicorn](https://www.uvicorn.org/) – A lightning-fast ASGI server implementation.
- **Async HTTP Client**: [HTTPX](https://www.python-httpx.org/) – Used for high-concurrency request forwarding/proxying.
- **Database**: SQLite (built-in standard library) with custom thread-safe connection pooling for logging.
- **Templating**: Jinja2 – For rendering the dashboard, logs explorer, and block screen.
- **Frontend Dashboard**: Tailwind CSS (for modern UI styling) & Chart.js (for real-time visualizations).

---

## ⚙️ Prerequisites

Ensure your system meets the following requirements:

- **Operating System**: Platform-agnostic (Windows, macOS, Linux supported).
- **Python**: version **3.8 or higher** installed. Verify using:
  ```bash
  python --version
  ```
- **Package Manager**: `pip` (Python package installer).

---

## 📥 Installation Guide

Follow these steps to set up WebGuard on your local machine:

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/hitarthruns/webguard.git
   cd webguard
   ```

2. **Create a Virtual Environment (Recommended)**:
   - On Windows:
     ```bash
     python -m venv venv
     .\venv\Scripts\activate
     ```
   - On macOS/Linux:
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

---

## 🚀 Usage Instructions

To launch the entire setup locally, run the protected backend and the WebGuard proxy server in parallel.

### Step 1: Start the Target Backend Server (Port 8000)
Run the mock server simulating your actual application that requires protection:
```bash
python mock_backend.py
```

### Step 2: Start the WebGuard WAF Proxy (Port 8081)
Run the firewall and reverse-proxy gateway in a separate terminal:
```bash
python app.py
```

### Step 3: Access WebGuard Dashboards
Once both servers are running, open your web browser to access:
- **Security Dashboard**: [http://127.0.0.1:8081/dashboard](http://127.0.0.1:8081/dashboard) — View live statistics and transaction metrics.
- **Logs Explorer**: [http://127.0.0.1:8081/logs](http://127.0.0.1:8081/logs) — Review, filter, and inspect blocked/allowed payloads.
- **Backend App (Via WAF)**: [http://127.0.0.1:8081/](http://127.0.0.1:8081/) — Requests sent here will be filtered. If clean, they will forward to the backend server (on port 8000) transparently.

---

## 📂 Project Structure

```text
waf/
├── app.py                  # Main FastAPI application hub, routes, and rate-limiting
├── config.py               # Global settings (ports, backend target, rate limit variables)
├── database.py             # SQLite log recorder, statistics aggregator, and search queries
├── models.py               # Pydantic schemas validating data shapes
├── mock_backend.py         # Mock backend server serving target endpoints
├── requirements.txt        # Package dependencies
├── test_waf.py             # Security integration test suite
├── templates/              # Jinja2 template screens
│   ├── block.html          # Custom WAF 403 Block screen
│   ├── dashboard.html      # Responsive analytics monitoring panel
│   └── logs.html           # Free-text searchable log audit table
└── waf/                    # Core WAF engine package
    ├── __init__.py
    ├── detector.py         # Deep packet inspection, decoding, and rule matcher
    ├── logger.py           # Interface wrapper targeting SQLite DB
    ├── proxy.py            # High-concurrency httpx.AsyncClient reverse proxy
    └── rules.py            # Precompiled security regex signatures
```

---

## 🧪 Testing & Validation

WebGuard includes an interactive test runner to simulate real-world web attacks and verify protective measures.

In a third terminal window, run the automated integration tests:
```bash
python test_waf.py
```

This test suite simulates:
- **Clean Traffic**: Simple GET/POST requests, query params, and logins.
- **SQLi Threats**: Attacks inside URLs, headers, and form-bodies.
- **XSS Threats**: Script elements inside query keys and custom headers.
- **Path Traversal**: Arbitrary directory query matching.
- **Rate-Limiter Action**: Triggers a 429 status by sending high-frequency requests.

---

## ⚙️ Security Rule Configurations

You can modify settings or toggle security features in `config.py`:

```python
# WAF Security Rule Controls - Toggle specific inspection engines
RULES_ENABLED = {
    "SQLi": True,
    "XSS": True,
    "Traversal": True
}

# Rate Limiting Parameters (Default: 60 requests per minute per IP)
RATE_LIMIT_LIMIT = 60
RATE_LIMIT_PERIOD = 60
```
