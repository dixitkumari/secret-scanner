"""
ai/classifier.py

Main entry point for Jiya's module:

    from ai.classifier import analyze_finding, analyze_findings

CLI:
    python -m ai.classifier tests/ai_cases.json
    python -m ai.classifier findings.json --no-ai     # rules only, no API
"""

import json
import os
import sys
import time

from dotenv import load_dotenv

from ai.prompt import SYSTEM_PROMPT, build_prompt

load_dotenv(".env.local")
load_dotenv()

MODEL_NAME = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")

ALLOWED_SEVERITY = ["Critical", "High", "Medium", "Low"]
ALLOWED_CLASSIFICATION = [
    "Likely Secret",
    "Potential PII",
    "Possible Test/Example Data",
    "False Positive",
    "Requires Verification",
]

# Fields copied straight from Dixit's finding into our output.
PASSTHROUGH_FIELDS = ["type", "file", "line", "value", "commit", "author", "date"]


# ---------- AI call ----------

def _get_client():
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return None
    from google import genai
    return genai.Client(api_key=api_key)


def _call_gemini(client, prompt: str) -> dict:
    from google.genai import types

    response = client.models.generate_content(
        model=MODEL_NAME,
        contents=prompt,
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            response_mime_type="application/json",
            temperature=0.0,  # consistent answers for the same input
        ),
    )
    return json.loads(response.text)


# ---------- Validation ----------

def _validate(raw: dict) -> dict:
    """Make sure the AI's answer has the right shape. Raises if it doesn't."""
    if not isinstance(raw, dict):
        raise ValueError("AI response is not a JSON object")

    classification = raw.get("classification")
    severity = raw.get("severity")

    if classification not in ALLOWED_CLASSIFICATION:
        raise ValueError(f"Bad classification: {classification}")
    if severity not in ALLOWED_SEVERITY:
        raise ValueError(f"Bad severity: {severity}")

    confidence = float(raw.get("confidence", 0.5))
    confidence = max(0.0, min(1.0, confidence))

    return {
        "classification": classification,
        "severity": severity,
        "confidence": round(confidence, 2),
        "reason": str(raw.get("reason", "")).strip(),
        "recommended_action": str(raw.get("recommended_action", "")).strip(),
    }


# ---------- Fallback (no AI) ----------

def _fallback(finding: dict) -> dict:
    """
    Simple rule-based triage. Used when the API key is missing, the API
    is down, or the AI returns garbage. Keeps the demo working.
    """
    ftype = str(finding.get("type", "")).upper()
    path = str(finding.get("file", "")).lower()
    context = str(finding.get("context", "")).lower()

    looks_like_example = (
        path.endswith(".md")
        or any(w in path for w in ("test", "sample", "example", "demo", "dummy"))
        or any(w in context for w in ("example", "dummy", "changeme", "fake"))
    )

    if looks_like_example:
        return {
            "classification": "Possible Test/Example Data",
            "severity": "Low",
            "confidence": 0.6,
            "reason": "The value appears in documentation or test-like content and may be an example rather than a real credential.",
            "recommended_action": "Verify that the value is not active, then ignore it or replace it with an obvious placeholder.",
        }

    if "PRIVATE_KEY" in ftype:
        return {
            "classification": "Likely Secret",
            "severity": "Critical",
            "confidence": 0.9,
            "reason": "A private key block was detected in the repository.",
            "recommended_action": "Treat the key as exposed: replace it, and remove it from the file and Git history.",
        }

    if "AWS" in ftype or "API" in ftype or "TOKEN" in ftype or "SECRET" in ftype:
        return {
            "classification": "Likely Secret",
            "severity": "Critical",
            "confidence": 0.8,
            "reason": "The value matches a cloud/API credential pattern and is not clearly example data.",
            "recommended_action": "Rotate the credential, remove it from the file, add the file to .gitignore, and purge it from Git history if committed.",
        }

    if ftype == "POSSIBLE_AADHAAR":
        return {
            "classification": "False Positive",
            "severity": "Low",
            "confidence": 0.5,
            "reason": "A 12-digit number was found, but nothing in the file or line suggests it is an Aadhaar number.",
            "recommended_action": "Quickly verify the number is not personal data; otherwise no action needed.",
        }

    if ftype in ("AADHAAR", "PAN"):
        return {
            "classification": "Potential PII",
            "severity": "High",
            "confidence": 0.75,
            "reason": "The value matches a government ID pattern and the surrounding context supports that.",
            "recommended_action": "Confirm whether this is real personal data. If so, remove it and replace it with synthetic data.",
        }

    if "PASSWORD" in ftype:
        return {
            "classification": "Likely Secret",
            "severity": "High",
            "confidence": 0.7,
            "reason": "A hardcoded password-like value was detected.",
            "recommended_action": "Move the password to environment variables or a secrets manager and change it.",
        }

    if "EMAIL" in ftype:
        return {
            "classification": "Potential PII",
            "severity": "Medium",
            "confidence": 0.5,
            "reason": "An email address was found; it may be personal data.",
            "recommended_action": "Verify whether it belongs to a real person and remove it if unnecessary.",
        }

    return {
        "classification": "Requires Verification",
        "severity": "Medium",
        "confidence": 0.4,
        "reason": "The pattern looks suspicious but there is not enough context to decide.",
        "recommended_action": "Manually review this finding.",
    }


# ---------- Public API ----------

def analyze_finding(finding: dict, use_ai: bool = True) -> dict:
    """Take ONE finding from Dixit's scanner, return the enriched result."""
    result = None
    source = "fallback"

    if use_ai:
        client = _get_client()
        if client is None:
            print("[ai] GEMINI_API_KEY not set - using fallback rules.", file=sys.stderr)
        else:
            prompt = build_prompt(finding)
            for attempt in range(2):  # one retry if the AI returns bad JSON
                try:
                    result = _validate(_call_gemini(client, prompt))
                    source = "ai"
                    break
                except Exception as e:
                    print(f"[ai] attempt {attempt + 1} failed: {e}", file=sys.stderr)
                    if attempt == 0:
                        time.sleep(15)  # wait before the retry so we don't burn quota

    if result is None:
        result = _fallback(finding)

    output = {k: finding[k] for k in PASSTHROUGH_FIELDS if k in finding}
    output.update(result)
    output["source"] = source  # "ai" or "fallback" (handy for debugging)
    return output


def analyze_findings(findings: list, use_ai: bool = True) -> list:
    """Analyze a whole list of findings (what Dixit's scan returns)."""
    results = []
    for i, f in enumerate(findings):
        if use_ai and i > 0:
            time.sleep(13)  # free tier allows 5 requests/minute
        results.append(analyze_finding(f, use_ai=use_ai))
    return results

# ---------- CLI ----------

def _main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    with open(sys.argv[1], encoding="utf-8") as f:
        findings = json.load(f)

    results = analyze_findings(findings, use_ai="--no-ai" not in sys.argv)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    _main()