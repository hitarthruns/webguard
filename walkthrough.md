# Walkthrough - WebGuard Implementation Complete

We have successfully built and verified **WebGuard** (formerly MiniWAF), a reverse-proxy Web Application Firewall!

---

## 🛠️ Accomplished Tasks

We implemented the complete architecture outlined in our implementation plan:

1. **Configuration & Data Layers**:
   - [config.py](file:///c:/Users/HITARTH/Desktop/waf/config.py): Configurable backend target, rate limiter boundaries, database path, and rulesets toggles.
   - [database.py](file:///c:/Users/HITARTH/Desktop/waf/database.py): SQLite thread-safe log writer, search query builder, and real-time dashboard statistics aggregator.
   - [models.py](file:///c:/Users/HITARTH/Desktop/waf/models.py): Pydantic data contract validation for logs and charts.

2. **Core Security Engine**:
   - [waf/rules.py](file:///c:/Users/HITARTH/Desktop/waf/waf/rules.py): Pre-compiled, case-insensitive regex signatures targeting SQL Injections, Cross-Site Scripting (XSS), and Path Traversals.
   - [waf/detector.py](file:///c:/Users/HITARTH/Desktop/waf/waf/detector.py): Deep packet inspection engine. Decodes and normalizes incoming URLs, paths, query inputs, headers, and request bodies (using URL decoding via `urllib.parse.unquote_plus`) before matching signatures.
   - [waf/logger.py](file:///c:/Users/HITARTH/Desktop/waf/waf/logger.py): Interface to log allowed and blocked connections into the database.
   - [waf/proxy.py](file:///c:/Users/HITARTH/Desktop/waf/waf/proxy.py): Streaming reverse-proxy using `httpx.AsyncClient` that forwards incoming headers, query parameters, body payloads, and outputs to the backend server.

3. **Routing, Middlewares & Dashboards**:
   - [app.py](file:///c:/Users/HITARTH/Desktop/waf/app.py): The main FastAPI hub. Implements sliding-window rate-limiting in memory by IP address. Includes dedicated endpoints for the dashboard, logs explorer API, and the catch-all proxy router. Serves static media assets (such as logo and favicon).
   - [templates/block.html](file:///c:/Users/HITARTH/Desktop/waf/templates/block.html): Custom "403 Forbidden" block screen displaying client IP, violation details, and transaction timestamps under WebGuard branding.
   - [templates/dashboard.html](file:///c:/Users/HITARTH/Desktop/waf/templates/dashboard.html): Modern dark-themed glassmorphism monitoring dashboard utilizing Tailwind CSS and Chart.js, featuring WebGuard's custom shield logo, favicons, and real-time statistics updating via background polling.
   - [templates/logs.html](file:///c:/Users/HITARTH/Desktop/waf/templates/logs.html): Complete logs inspector allowing category filters, free-text searches, pagination, and inspection modals to review blocked request payloads.

4. **Testing & Target**:
   - [mock_backend.py](file:///c:/Users/HITARTH/Desktop/waf/mock_backend.py): Protected mock server on port `8000` providing target endpoints.
   - [test_waf.py](file:///c:/Users/HITARTH/Desktop/waf/test_waf.py): Interactive security test runner.

---

## 🧪 Verification & Security Test Run

The test script [test_waf.py](file:///c:/Users/HITARTH/Desktop/waf/test_waf.py) was run against the active WebGuard gateway. Here are the results:

```text
======================================================================
                 WebGuard Integration & Security Tests                
======================================================================

[PASSED] Clean Request: Home | Status: 200
[PASSED] Clean Request: Search parameter | Status: 200
[PASSED] Clean Request: Form authentication login | Status: 200
[PASSED] Attack: SQLi in URL query (UNION SELECT) | Status: 403
[PASSED] Attack: SQLi in body (OR 1=1 auth bypass) | Status: 403
[PASSED] Attack: SQLi in Header field (time delay sleep) | Status: 403
[PASSED] Attack: XSS in URL query (script tags) | Status: 403
[PASSED] Attack: XSS in custom Header (onerror loader) | Status: 403
[PASSED] Attack: Directory Traversal (Unix passwd file) | Status: 403
[PASSED] Attack: Directory Traversal (Windows system config) | Status: 403

----------------------------------------------------------------------
Testing Rate Limiter (Configured: 60 req/min)...
----------------------------------------------------------------------
[PASSED] Rate limiting triggered successfully at Request #51 with Status: 429.

======================================================================
Test Summary: 11 Passed, 0 Failed
======================================================================
```

---

## 🚀 How to Run WebGuard Locally

Follow these steps to spin up the servers and explore the dashboard:

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Start the Target Backend Server (Port 8000)
In one terminal window, run:
```bash
python mock_backend.py
```

### 3. Start WebGuard Server (Port 8081)
In a second terminal window, run:
```bash
python app.py
```

### 4. Run the Security Tests
In a third terminal window, run:
```bash
python test_waf.py
```

### 5. Access the Web Interfaces
Open your browser and navigate to:
- **WebGuard Dashboard**: `http://127.0.0.1:8081/dashboard`
- **WebGuard Logs Explorer**: `http://127.0.0.1:8081/logs`
- **Backend App via WebGuard proxy**: `http://127.0.0.1:8081/` (Safe paths forward to backend; attack paths block and display the custom shield page).
