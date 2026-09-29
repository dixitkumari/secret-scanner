from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlparse
import subprocess

from flask import Flask, jsonify, request
from flask_cors import CORS

from scanner.git_scanner import scan_repository
from ai.classifier import analyze_findings


app = Flask(__name__)
CORS(app)


def transform_finding(raw_finding, analyzed_finding, index):
    return {
        "id": f"{raw_finding.get('commit', 'unknown')}-{index}",
        "type": raw_finding.get("type", "UNKNOWN"),

        # AI-generated fields
        "severity": analyzed_finding.get(
            "severity",
            "Low"
        ),
        "classification": analyzed_finding.get(
            "classification",
            "Requires Verification"
        ),
        "confidence": analyzed_finding.get(
            "confidence",
            0.0
        ),
        "reason": analyzed_finding.get(
            "reason",
            ""
        ),
        "recommended_action": analyzed_finding.get(
            "recommended_action",
            ""
        ),
        "source": analyzed_finding.get(
            "source",
            "fallback"
        ),

        # Original scanner fields
        "file": raw_finding.get(
            "file",
            "Unknown"
        ),
        "line": raw_finding.get(
            "line",
            0
        ),
        "value": raw_finding.get(
            "value",
            ""
        ),
        "context": raw_finding.get(
            "context",
            ""
        ),
        "commit": raw_finding.get(
            "commit",
            "Unknown"
        ),
        "author": raw_finding.get(
            "author",
            "Unknown"
        ),
        "date": raw_finding.get(
            "date",
            ""
        ),
    }


def validate_github_url(repo_url):
    parsed = urlparse(repo_url)

    if parsed.scheme != "https":
        raise ValueError(
            "Please use a GitHub HTTPS URL."
        )

    if parsed.netloc.lower() != "github.com":
        raise ValueError(
            "Only GitHub repository URLs are supported."
        )

    parts = [
        part
        for part in parsed.path.strip("/").split("/")
        if part
    ]

    if len(parts) < 2:
        raise ValueError(
            "Please enter a valid GitHub repository URL."
        )

    return repo_url.rstrip("/")


def clone_repository(repo_url, destination):
    subprocess.run(
        [
            "git",
            "clone",
            repo_url,
            str(destination),
        ],
        check=True,
        capture_output=True,
        text=True,
    )


@app.get("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "message": "SentinelGit API is running"
    })


@app.post("/api/scan")
def scan():
    try:
        data = request.get_json(silent=True) or {}

        repo_url = data.get(
            "repoUrl",
            ""
        ).strip()

        if not repo_url:
            return jsonify({
                "error": "Repository URL is required",
                "message": "Please provide a GitHub repository URL."
            }), 400

        repo_url = validate_github_url(
            repo_url
        )

        with TemporaryDirectory(
            prefix="sentinelgit-"
        ) as temp_dir:

            repo_path = (
                Path(temp_dir)
                / "repository"
            )

            # 1. Clone GitHub repository
            clone_repository(
                repo_url,
                repo_path
            )

            # 2. Run existing scanner
            raw_findings = scan_repository(
                str(repo_path)
            )

            # 3. Run Jiya's AI classifier
            #
            # use_ai=False currently means
            # Jiya's rule-based fallback is used.
            #
            # This keeps the dashboard fast while
            # we verify the complete integration.
            analyzed_findings = analyze_findings(
                raw_findings,
                use_ai=False
            )

            # 4. Combine scanner + AI results
            findings = [
                transform_finding(
                    raw_finding,
                    analyzed_finding,
                    index
                )
                for index, (
                    raw_finding,
                    analyzed_finding
                ) in enumerate(
                    zip(
                        raw_findings,
                        analyzed_findings
                    )
                )
            ]

            # 5. Calculate summary
            critical = sum(
                1
                for finding in findings
                if finding["severity"] == "Critical"
            )

            high = sum(
                1
                for finding in findings
                if finding["severity"] == "High"
            )

            medium = sum(
                1
                for finding in findings
                if finding["severity"] == "Medium"
            )

            low = sum(
                1
                for finding in findings
                if finding["severity"] == "Low"
            )

            commits = {
                finding["commit"]
                for finding in findings
                if finding["commit"] != "Unknown"
            }

            files = {
                finding["file"]
                for finding in findings
                if finding["file"] != "Unknown"
            }

            summary = {
                "findings": len(findings),
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "commitsScanned": len(commits),
                "filesScanned": len(files),
            }

            return jsonify({
                "findings": findings,
                "summary": summary,
                "scannedAt": datetime.now(
                    timezone.utc
                ).isoformat(),
                "repository": repo_url,
            })

    except subprocess.CalledProcessError as error:

        error_message = (
            error.stderr.strip()
            if error.stderr
            else "Unable to clone the GitHub repository."
        )

        return jsonify({
            "error": "Repository clone failed",
            "message": error_message,
        }), 400

    except ValueError as error:

        return jsonify({
            "error": "Invalid repository URL",
            "message": str(error),
        }), 400

    except Exception as error:

        return jsonify({
            "error": "Repository scan failed",
            "message": str(error),
        }), 500


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
    )