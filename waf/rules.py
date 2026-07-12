import re

# Raw WAF detection rules using regex patterns for SQLi, XSS, and Directory Traversal.
# Using standard case-insensitive (?i) flags where applicable.
RAW_RULES = {
    "SQLi": [
        r"(?i)\bunion\s+all\s+select\b",
        r"(?i)\bunion\s+select\b",
        r"(?i)\bselect\s+.*\s+from\b",
        r"(?i)\b(?:or|and)\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?", # e.g. OR 1=1
        r"(?i)\b(?:sleep|benchmark|pg_sleep|dbms_lock\.sleep)\s*\(", # Time-based attacks
        r"(?i)(?:--|\/\*|\*\/|#)", # Comments
        r"(?i)\b(?:drop|delete|insert|update|alter|create|truncate|exec|grant)\b" # Dangerous commands
    ],
    "XSS": [
        r"(?i)<script.*?>.*?</script>",
        r"(?i)<script.*?>",
        r"(?i)</script>",
        r"(?i)javascript\s*:", # javascript uri
        r"(?i)\bon(?:error|load|click|mouseover|focus|submit|change|keydown|keyup)\s*=", # DOM event handlers
        r"(?i)\b(?:alert|confirm|prompt|eval)\s*\(",
        r"(?i)<iframe.*?src=.*?javascript:",
        r"(?i)<svg.*?onload\b",
        r"(?i)<img.*?src=.*?onerror\b"
    ],
    "Traversal": [
        r"\.\./", # Unix traversal
        r"\.\.\\", # Windows traversal
        r"(?i)\betc/passwd\b",
        r"(?i)\betc/shadow\b",
        r"(?i)\betc/hosts\b",
        r"(?i)\bwindows/win\.ini\b",
        r"(?i)\bwin\.ini\b",
        r"(?i)\bboot\.ini\b",
        r"(?i)\bbin/sh\b",
        r"(?i)\bbin/bash\b"
    ]
}

# Compile the patterns on startup to maximize detection performance
COMPILED_RULES = {
    category: [re.compile(pattern) for pattern in patterns]
    for category, patterns in RAW_RULES.items()
}

def check_payload(content: str) -> tuple:
    """
    Checks a given string payload against all active compiled rules.
    Returns:
        (is_attack: bool, category: str, matched_pattern: str)
    """
    if not content:
        return False, "", ""
        
    for category, patterns in COMPILED_RULES.items():
        for pattern in patterns:
            if pattern.search(content):
                return True, category, pattern.pattern
                
    return False, "", ""
