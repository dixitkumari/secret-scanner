from ai.classifier import analyze_finding, ALLOWED_SEVERITY, ALLOWED_CLASSIFICATION
import json, os

CASES_PATH = os.path.join(os.path.dirname(__file__), "ai_cases.json")
CASES = json.load(open(CASES_PATH, encoding="utf-8"))


def run(i):
    return analyze_finding(CASES[i], use_ai=False)


def test_aws_in_env_is_critical():
    r = run(0)
    assert r["severity"] == "Critical" and r["classification"] == "Likely Secret"

def test_private_key_is_critical():
    assert run(1)["severity"] == "Critical"

def test_aadhaar_csv_is_high():
    r = run(2)
    assert r["severity"] == "High" and r["classification"] == "Potential PII"

def test_random_12_digit_is_low():
    assert run(3)["severity"] == "Low"

def test_readme_example_is_low():
    r = run(4)
    assert r["severity"] == "Low" and "Example" in r["classification"]

def test_output_shape():
    for i in range(len(CASES)):
        r = run(i)
        assert r["severity"] in ALLOWED_SEVERITY
        assert r["classification"] in ALLOWED_CLASSIFICATION
        assert 0 <= r["confidence"] <= 1
        assert r["reason"] and r["recommended_action"]