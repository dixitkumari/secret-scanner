"""
SentinelGit dashboard API.

Runs a small local HTTP API that connects the React dashboard
to the real scanner implemented by Dixit's scanner module.

Run from the dashboard directory:

    python server.py

The React/Vite development server proxies /api requests to this server.
"""

import json
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


# Repository root:
# secret-scanner/
# ├── scanner/
# ├── main.py
# └── dashboard/
ROOT = Path(__file__).resolve().parent.parent

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from git import Repo
from scanner.git_scanner import scan_repository


HOST = "127.0.0.1"
PORT = 8000
MAX_COMMITS = 50


SEVERITY_MAP = {
    "PRIVATE_KEY": "Critical",
    "AWS_ACCESS_KEY": "Critical",
    "DB_CONNECTION_STRING": "Critical",
    "API_KEY": "High",
    "PASSWORD": "High",
    "PAN": "High",
    "AADHAAR": "High",
    "EMAIL": "Medium",
    "POSSIBLE_AADHAAR": "Low",
}


CLASSIFICATION_MAP = {
    "PRIVATE_KEY": "Likely Secret",
    "AWS_ACCESS_KEY": "Likely Secret",
    "DB_CONNECTION_STRING": "Likely Secret",
    "API_KEY": "Likely Secret",
    "PASSWORD": "Likely Secret",
    "PAN": "Potential PII",
    "AADHAAR": "Potential PII",
    "EMAIL": "Potential PII",
    "POSSIBLE_AADHAAR": "Potential PII",
}


REASON_MAP = {
    "PRIVATE_KEY": (
        "The scanner detected a private key block in an added Git line."
    ),
    "AWS_ACCESS_KEY": (
        "The detected value matches the structure of an AWS access key."
    ),
    "DB_CONNECTION_STRING": (
        "The line contains a database connection string with embedded credentials."
    ),
    "API_KEY": (
        "The detected string matches a variable pattern commonly used for API keys or tokens."
    ),
    "PASSWORD": (
        "The line contains a hardcoded password-like value."
    ),
    "PAN": (
        "The detected value matches the standard structure of an Indian PAN number."
    ),
    "AADHAAR": (
        "The scanner found a 12-digit value in Aadhaar-related context."
    ),
    "EMAIL": (
        "The detected value appears to be an email address."
    ),
    "POSSIBLE_AADHAAR": (
        "The value is a 12-digit number that may represent Aadhaar, "
        "but the scanner could not confirm the context."
    ),
}


ACTION_MAP = {
    "PRIVATE_KEY": (
        "Rotate the key and purge the credential from Git history."
    ),
    "AWS_ACCESS_KEY": (
        "Rotate the AWS credential and remove it from the repository."
    ),
    "DB_CONNECTION_STRING": (
        "Rotate the database credential and move it to a secure environment variable."
    ),
    "API_KEY": (
        "Rotate the credential and move it to a secure environment variable."
    ),
    "PASSWORD": (
        "Change the credential and move it to a secure secret store."
    ),
    "PAN": (
        "Review whether the personal data is necessary and restrict its exposure."
    ),
    "AADHAAR": (
        "Verify the value and remove sensitive personal data if unnecessary."
    ),
    "EMAIL": (
        "Review whether the personal data is necessary and restrict its exposure."
    ),
    "POSSIBLE_AADHAAR": (
        "Verify the value and remove sensitive personal data if unnecessary."
    ),
}


def build_finding(raw_finding, finding_id):
    """
    Convert Dixit's raw scanner finding into the shape expected by
    the SentinelGit React dashboard.
    """

    finding_type = raw_finding.get("type", "UNKNOWN")

    raw_confidence = raw_finding.get("confidence")

    # Dixit's Aadhaar detector currently returns textual confidence:
    # "high", "medium", or "low".
    # Other detectors do not provide AI confidence yet.
    confidence = None

    if isinstance(raw_confidence, str):
        confidence_map = {
            "high": 0.90,
            "medium": 0.70,
            "low": 0.40,
        }
        confidence = confidence_map.get(raw_confidence.lower())

    return {
        "id": finding_id,
        "type": finding_type,
        "file": raw_finding.get("file", "Unknown"),
        "line": raw_finding.get("line", 0),
        "commit": raw_finding.get("commit", "Unknown"),
        "author": raw_finding.get("author", "Unknown"),
        "date": raw_finding.get(
            "date",
            datetime.now(timezone.utc).isoformat(),
        ),
        "classification": CLASSIFICATION_MAP.get(
            finding_type,
            "Needs Review",
        ),
        "severity": SEVERITY_MAP.get(
            finding_type,
            "Medium",
        ),
        "confidence": confidence,
        "reason": REASON_MAP.get(
            finding_type,
            "The scanner detected a potentially sensitive value.",
        ),
        "recommendedAction": ACTION_MAP.get(
            finding_type,
            "Review the finding and remove sensitive information if necessary.",
        ),
    }


def scan_repo():
    """
    Run the real Git scanner against the repository containing this project.
    """

    repo = Repo(ROOT)

    raw_findings = scan_repository(
        str(ROOT),
        max_commits=MAX_COMMITS,
    )

    findings = [
        build_finding(raw_finding, index + 1)
        for index, raw_finding in enumerate(raw_findings)
    ]

    commits_scanned = len(
        list(repo.iter_commits(max_count=MAX_COMMITS))
    )

    try:
        tracked_files = repo.git.ls_files().splitlines()
        files_scanned = len(
            [file for file in tracked_files if file.strip()]
        )
    except Exception:
        files_scanned = 0

    critical_count = sum(
        1 for finding in findings
        if finding["severity"] == "Critical"
    )

    high_count = sum(
        1 for finding in findings
        if finding["severity"] == "High"
    )

    medium_count = sum(
        1 for finding in findings
        if finding["severity"] == "Medium"
    )

    low_count = sum(
        1 for finding in findings
        if finding["severity"] == "Low"
    )

    return {
        "findings": findings,
        "summary": {
            "findings": len(findings),
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "commitsScanned": commits_scanned,
            "filesScanned": files_scanned,
        },
        "scannedAt": datetime.now(
            timezone.utc
        ).astimezone().isoformat(),
    }


class DashboardHandler(BaseHTTPRequestHandler):

    def _send_json(self, data, status=200):
        payload = json.dumps(data).encode("utf-8")

        self.send_response(status)
        self.send_header(
            "Content-Type",
            "application/json; charset=utf-8",
        )
        self.send_header(
            "Content-Length",
            str(len(payload)),
        )
        self.send_header(
            "Access-Control-Allow-Origin",
            "http://localhost:5173",
        )
        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type",
        )
        self.end_headers()

        self.wfile.write(payload)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header(
            "Access-Control-Allow-Origin",
            "http://localhost:5173",
        )
        self.send_header(
            "Access-Control-Allow-Methods",
            "POST, OPTIONS",
        )
        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type",
        )
        self.end_headers()

    def do_POST(self):
        if self.path != "/api/scan":
            self._send_json(
                {"error": "Endpoint not found."},
                status=404,
            )
            return

        try:
            result = scan_repo()
            self._send_json(result)

        except Exception as error:
            self._send_json(
                {
                    "error": str(error),
                    "message": (
                        "The repository scan could not be completed."
                    ),
                },
                status=500,
            )

    def log_message(self, format, *args):
        print(f"[SentinelGit API] {format % args}")


def main():
    server = HTTPServer(
        (HOST, PORT),
        DashboardHandler,
    )

    print()
    print("========================================")
    print(" SentinelGit Dashboard API")
    print("========================================")
    print(f" API running at http://{HOST}:{PORT}")
    print(f" Repository: {ROOT}")
    print(f" Maximum commits per scan: {MAX_COMMITS}")
    print("========================================")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping SentinelGit API...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()