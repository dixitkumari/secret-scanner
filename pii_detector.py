"""
pii_detector.py

Detects personally identifiable information:
- Email addresses
- PAN numbers (India)
- Aadhaar numbers (India) -- context-aware, not a blind 12-digit match

The Aadhaar detector deliberately looks at the file name and surrounding
column/header context before flagging a plain 12-digit number, since a
bare 12-digit number is extremely common (order IDs, phone-ish strings,
random identifiers) and would otherwise flood the output with noise.
"""

import os
import re

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# Standard PAN format: 5 letters, 4 digits, 1 letter
PAN_RE = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")

# Bare 12-digit number (candidate Aadhaar, needs context to confirm)
TWELVE_DIGIT_RE = re.compile(r"\b\d{12}\b")

# Filename / header hints that raise our confidence a 12-digit number
# is actually an Aadhaar number rather than some other identifier.
AADHAAR_CONTEXT_HINTS = (
    "aadhaar", "aadhar", "adhaar", "uidai", "uid_number", "uid_no",
)


def _filename_suggests_aadhaar(file_path: str) -> bool:
    name = os.path.basename(file_path).lower()
    return any(hint in name for hint in AADHAAR_CONTEXT_HINTS)


def _line_suggests_aadhaar(line: str) -> bool:
    lowered = line.lower()
    return any(hint in lowered for hint in AADHAAR_CONTEXT_HINTS)


def detect_pii_in_line(line: str, line_number: int, file_path: str):
    """
    Run all PII detectors against a single line of text.

    Returns a list of finding dicts, same shape as secret_detector's output,
    plus a "confidence" field for the context-sensitive Aadhaar case.
    """
    findings = []
    context = line.strip()

    # Email
    for match in EMAIL_RE.finditer(line):
        findings.append({
            "type": "EMAIL",
            "file": file_path,
            "line": line_number,
            "value": match.group(0),
            "context": context,
        })

    # PAN
    for match in PAN_RE.finditer(line):
        findings.append({
            "type": "PAN",
            "file": file_path,
            "line": line_number,
            "value": match.group(0)[:5] + "****" + match.group(0)[-1],
            "context": context,
        })

    # Aadhaar -- context aware
    for match in TWELVE_DIGIT_RE.finditer(line):
        value = match.group(0)
        filename_hit = _filename_suggests_aadhaar(file_path)
        line_hit = _line_suggests_aadhaar(line)

        if filename_hit or line_hit:
            findings.append({
                "type": "AADHAAR",
                "file": file_path,
                "line": line_number,
                "value": value[:4] + "****" + value[-4:],
                "context": context,
                "confidence": "high" if filename_hit else "medium",
            })
        else:
            # Still record it, but as low confidence / likely benign.
            # Milestone-3+ (AI layer) can decide whether to surface this
            # at all; for now we keep it so nothing is silently dropped.
            findings.append({
                "type": "POSSIBLE_AADHAAR",
                "file": file_path,
                "line": line_number,
                "value": value[:4] + "****" + value[-4:],
                "context": context,
                "confidence": "low",
            })

    return findings
