"""
secret_detector.py

Regex-based detection for common secret types:
- AWS Access Key
- Generic API key
- Private key blocks
- Hardcoded passwords
- Database connection strings with embedded credentials

Each detector function takes a single line of text and returns a list of
finding dicts (empty list if nothing found). Keeping detectors per-line
makes it trivial to plug into both the file scanner and the git scanner.
"""

import re

# --- Patterns -----------------------------------------------------------

AWS_ACCESS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")

# Generic "looks like an API key" pattern: a variable name containing
# key/token/secret, assigned to a long-ish random-looking string.
GENERIC_API_KEY_RE = re.compile(
    r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)"
    r"\s*[:=]\s*['\"]?([A-Za-z0-9_\-/+]{16,})['\"]?"
)

PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
)

PASSWORD_RE = re.compile(
    r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^'\"\s]{4,})['\"]?"
)

# Common obviously-fake/placeholder values we should NOT flag.
PLACEHOLDER_VALUES = {
    "changeme", "your-key-here", "your_password_here", "xxxx", "placeholder",
    "example", "test", "password", "123456", "secret", "<password>",
    "<api_key>", "todo", "fixme", "insert_key_here",
}

# Connection strings like postgres://user:password@host:5432/db
DB_CONN_STRING_RE = re.compile(
    r"(?i)(postgres|postgresql|mysql|mongodb(\+srv)?|redis)://"
    r"[^:/\s]+:([^@/\s]+)@[^\s'\"]+"
)


def _mask(value: str) -> str:
    """Mask a secret value for safe display, keeping only a short prefix."""
    if len(value) <= 4:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 4)


def _is_placeholder(value: str) -> bool:
    return value.strip().lower() in PLACEHOLDER_VALUES


def detect_secrets_in_line(line: str, line_number: int, file_path: str):
    """
    Run all secret detectors against a single line of text.

    Returns a list of finding dicts:
    {
        "type": str,
        "file": str,
        "line": int,
        "value": str,      # masked
        "context": str,    # original line, trimmed
    }
    """
    findings = []
    context = line.strip()

    # AWS Access Key
    for match in AWS_ACCESS_KEY_RE.finditer(line):
        value = match.group(0)
        findings.append({
            "type": "AWS_ACCESS_KEY",
            "file": file_path,
            "line": line_number,
            "value": _mask(value),
            "context": context,
        })

    # Generic API key / token
    for match in GENERIC_API_KEY_RE.finditer(line):
        value = match.group(2)
        if _is_placeholder(value):
            continue
        findings.append({
            "type": "API_KEY",
            "file": file_path,
            "line": line_number,
            "value": _mask(value),
            "context": context,
        })

    # Private key block
    if PRIVATE_KEY_RE.search(line):
        findings.append({
            "type": "PRIVATE_KEY",
            "file": file_path,
            "line": line_number,
            "value": "-----BEGIN PRIVATE KEY-----",
            "context": context,
        })

    # Hardcoded password
    for match in PASSWORD_RE.finditer(line):
        value = match.group(2)
        if _is_placeholder(value):
            continue
        findings.append({
            "type": "PASSWORD",
            "file": file_path,
            "line": line_number,
            "value": _mask(value),
            "context": context,
        })

    # DB connection string with embedded password
    for match in DB_CONN_STRING_RE.finditer(line):
        value = match.group(3)
        if _is_placeholder(value):
            continue
        findings.append({
            "type": "DB_CONNECTION_STRING",
            "file": file_path,
            "line": line_number,
            "value": _mask(value),
            "context": context,
        })

    return findings
