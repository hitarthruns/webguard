import httpx
import time
import sys

WAF_URL = "http://127.0.0.1:8081"

def run_tests():
    print("======================================================================")
    print("                 WebGuard Integration & Security Tests                ")
    print("======================================================================\n")
    
    client = httpx.Client(base_url=WAF_URL, timeout=10.0)
    
    # 1. Functional & Attack Vector Test Suite
    test_cases = [
        # --- Clean Traffic (Should return 200 OK) ---
        {
            "name": "Clean Request: Home",
            "method": "GET",
            "url": "/",
            "headers": {},
            "data": {},
            "expected_status": 200
        },
        {
            "name": "Clean Request: Search parameter",
            "method": "GET",
            "url": "/search?q=python+tutorials",
            "headers": {},
            "data": {},
            "expected_status": 200
        },
        {
            "name": "Clean Request: Form authentication login",
            "method": "POST",
            "url": "/login",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "data": {"username": "hitarth", "password": "SuperSecurePassword123!"},
            "expected_status": 200
        },
        
        # --- SQL Injection Attacks (Should return 403 Forbidden) ---
        {
            "name": "Attack: SQLi in URL query (UNION SELECT)",
            "method": "GET",
            "url": "/search?q=1+union+select+null,username,password+from+users",
            "headers": {},
            "data": {},
            "expected_status": 403
        },
        {
            "name": "Attack: SQLi in body (OR 1=1 auth bypass)",
            "method": "POST",
            "url": "/login",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "data": {"username": "admin' OR '1'='1", "password": "any"},
            "expected_status": 403
        },
        {
            "name": "Attack: SQLi in Header field (time delay sleep)",
            "method": "GET",
            "url": "/profile",
            "headers": {"User-Agent": "Mozilla/5.0; sleep(10)"},
            "data": {},
            "expected_status": 403
        },

        # --- Cross Site Scripting Attacks (Should return 403 Forbidden) ---
        {
            "name": "Attack: XSS in URL query (script tags)",
            "method": "GET",
            "url": "/search?q=<script>alert('XSS')</script>",
            "headers": {},
            "data": {},
            "expected_status": 403
        },
        {
            "name": "Attack: XSS in custom Header (onerror loader)",
            "method": "GET",
            "url": "/profile",
            "headers": {"X-Custom-Client": "<img src=x onerror=alert(document.cookie)>"},
            "data": {},
            "expected_status": 403
        },

        # --- Directory Traversal Attacks (Should return 403 Forbidden) ---
        {
            "name": "Attack: Directory Traversal (Unix passwd file)",
            "method": "GET",
            "url": "/get-file?file=../../../../etc/passwd",
            "headers": {},
            "data": {},
            "expected_status": 403
        },
        {
            "name": "Attack: Directory Traversal (Windows system config)",
            "method": "GET",
            "url": "/get-file?file=..\\..\\windows\\win.ini",
            "headers": {},
            "data": {},
            "expected_status": 403
        }
    ]

    passed_count = 0
    failed_count = 0

    for tc in test_cases:
        name = tc["name"]
        method = tc["method"]
        url = tc["url"]
        headers = tc["headers"]
        data = tc["data"]
        expected = tc["expected_status"]
        
        try:
            if method == "GET":
                response = client.get(url, headers=headers)
            elif method == "POST":
                response = client.post(url, data=data, headers=headers)
            else:
                continue
                
            status = response.status_code
            if status == expected:
                print(f"[\033[92mPASSED\033[0m] {name} | Status: {status}")
                passed_count += 1
            else:
                print(f"[\033[91mFAILED\033[0m] {name} | Got Status: {status} (Expected: {expected})")
                failed_count += 1
        except Exception as e:
            print(f"[\033[91mERROR\033[0m]  {name} | Connection failed: {e}")
            failed_count += 1

    # 2. Rate Limiting Tests (Should return 429 Too Many Requests)
    print("\n----------------------------------------------------------------------")
    print("Testing Rate Limiter (Configured: 60 req/min)...")
    print("----------------------------------------------------------------------")
    
    rate_limited = False
    for req_num in range(1, 75):
        try:
            # Send requests rapidly to trigger rate limiting
            response = client.get("/")
            if response.status_code == 429:
                print(f"[\033[92mPASSED\033[0m] Rate limiting triggered successfully at Request #{req_num} with Status: 429.")
                rate_limited = True
                break
        except Exception as e:
            print(f"Request #{req_num} failed with connection error: {e}")
            break
            
    if not rate_limited:
        print("[\033[91mFAILED\033[0m] Rate limiter failed to trigger within 75 fast requests.")
        failed_count += 1
    else:
        passed_count += 1

    print("\n======================================================================")
    print(f"Test Summary: {passed_count} Passed, {failed_count} Failed")
    print("======================================================================\n")
    
    if failed_count > 0:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    run_tests()
