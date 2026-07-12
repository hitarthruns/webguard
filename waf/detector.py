from fastapi import Request
import urllib.parse
from waf.rules import check_payload
from config import RULES_ENABLED

async def inspect_request(request: Request) -> tuple:
    """
    Inspects URL path, query params, headers, and request body after normalization (URL decoding).
    Returns:
        (is_attack: bool, category: str, matched_payload: str, body_bytes: bytes)
    """
    # 1. Read request body safely
    try:
        body_bytes = await request.body()
        body_str = body_bytes.decode('utf-8', errors='ignore')
    except Exception:
        body_bytes = b""
        body_str = ""

    # 2. Check path (URL decoded)
    path = request.url.path
    decoded_path = urllib.parse.unquote(path)
    is_attack, category, payload = check_payload(decoded_path)
    if is_attack and RULES_ENABLED.get(category, True):
        return True, category, f"Path: {decoded_path} (Triggered: {payload})", body_bytes

    # 3. Check query parameters (URL decoded)
    query_string = request.url.query
    if query_string:
        decoded_query = urllib.parse.unquote_plus(query_string)
        is_attack, category, payload = check_payload(decoded_query)
        if is_attack and RULES_ENABLED.get(category, True):
            return True, category, f"Query: {decoded_query} (Triggered: {payload})", body_bytes

    # 4. Check headers (URL decoded)
    # Inspect user-agent, referer, cookies, and other headers
    for name, value in request.headers.items():
        # Ignore headers that are strictly machine-generated or highly unlikely to contain injections
        if name.lower() in (
            "connection", "accept-encoding", "host", "content-length", "date", 
            "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", 
            "accept", "accept-language", "accept-charset", "content-type"
        ):
            continue
        decoded_value = urllib.parse.unquote_plus(value)
        is_attack, category, payload = check_payload(decoded_value)
        if is_attack and RULES_ENABLED.get(category, True):
            return True, category, f"Header [{name}]: {decoded_value} (Triggered: {payload})", body_bytes

    # 5. Check body (URL decoded)
    if body_str:
        decoded_body = urllib.parse.unquote_plus(body_str)
        is_attack, category, payload = check_payload(decoded_body)
        if is_attack and RULES_ENABLED.get(category, True):
            # Truncate logged payload if it is extremely long
            display_payload = decoded_body if len(decoded_body) < 200 else f"{decoded_body[:200]}..."
            return True, category, f"Body: {display_payload} (Triggered: {payload})", body_bytes

    return False, "", "", body_bytes
