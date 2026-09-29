"""
ai/prompt.py

Builds the prompt sent to the AI. Keeping this separate from classifier.py
means we can tune the wording without touching the logic.
"""

import os
import re

SYSTEM_PROMPT = """You are a Git security analyst reviewing findings from an
automated secret/PII scanner. Scanners produce false positives, so your job is
to use context to decide how serious each finding really is.

Rules:
- NEVER claim a credential is definitely live or active. You cannot verify that.
  Use wording like "potential credential", "likely secret", "possible PII",
  "possible test data", "requires verification".
- Consider: file name, file type, variable name, surrounding text, and whether
  the value looks like an example/dummy (words like EXAMPLE, test, dummy, sample).
- A bare 12-digit number is NOT automatically Aadhaar. Use context.

Severity guide:
- Critical: cloud/API credentials, private keys, highly sensitive auth secrets
- High: Aadhaar/PAN/customer PII, real-looking passwords
- Medium: suspicious tokens or values that need verification
- Low: example/test data, documentation samples, likely false positives

Allowed "classification" values (use exactly one):
"Likely Secret", "Potential PII", "Possible Test/Example Data",
"False Positive", "Requires Verification"

Respond with ONLY a JSON object with exactly these keys:
{
  "classification": string,
  "severity": "Critical" | "High" | "Medium" | "Low",
  "confidence": number between 0 and 1,
  "reason": string (1-2 sentences, why it was flagged and how context affected the decision),
  "recommended_action": string (1-2 sentences, what the developer should do)
}"""

FILE_TYPE_HINTS = {
    ".env": "environment configuration",
    ".csv": "CSV data file",
    ".md": "documentation",
    ".txt": "text file",
    ".py": "Python source code",
    ".js": "JavaScript source code",
    ".json": "JSON data/config",
    ".yml": "YAML config",
    ".yaml": "YAML config",
    ".pem": "key/certificate file",
}

# Words that suggest a value is dummy data. We keep these visible to the AI.
SAFE_WORDS = ("example", "test", "dummy", "sample", "fake", "changeme", "xxxx")


def describe_file_type(path: str) -> str:
    name = os.path.basename(path).lower()
    if name.startswith(".env"):
        return "environment configuration"
    ext = os.path.splitext(name)[1]
    return FILE_TYPE_HINTS.get(ext, "unknown")


def redact_context(context: str) -> str:
    """
    Dixit's `context` line can contain the full unmasked value.
    Before sending it to an external API, mask long tokens and 12-digit
    numbers. We leave tokens containing words like EXAMPLE/test alone,
    because those words are exactly the clue the AI needs.
    """
    def _mask(match):
        token = match.group(0)
        if any(w in token.lower() for w in SAFE_WORDS):
            return token
        return token[:4] + "*" * (len(token) - 4)

    context = re.sub(r"[A-Za-z0-9/+_\-]{16,}", _mask, context)
    context = re.sub(r"\b\d{12}\b", "<12-digit-number>", context)
    return context


def build_prompt(finding: dict) -> str:
    file_path = finding.get("file", "unknown")
    context = redact_context(str(finding.get("context", "")))

    return f"""Analyze this suspicious finding.

File: {file_path}
File type: {describe_file_type(file_path)}
Line: {finding.get("line", "unknown")}
Detected pattern: {finding.get("type", "unknown")}
Masked value: {finding.get("value", "unknown")}
Context line: {context}

Decide whether this is likely a real sensitive-data leak, a false positive,
or example/test data. Return the JSON object described in your instructions."""