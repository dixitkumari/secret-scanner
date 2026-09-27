"""
file_scanner.py

Milestone 1 + 2: walk a directory tree and run secret/PII detectors
against every text file, line by line.

This has no Git awareness yet -- it's a plain filesystem scan.
Git-aware scanning (Milestone 3+) lives in git_scanner.py and reuses
these same detector functions.
"""

import os

from scanner.secret_detector import detect_secrets_in_line
from scanner.pii_detector import detect_pii_in_line

# Directories we never want to walk into.
IGNORED_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__"}

# Skip obviously binary / non-text extensions to avoid noise and errors.
SKIPPED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".tar", ".gz",
    ".exe", ".dll", ".so", ".pyc", ".ico", ".woff", ".woff2", ".ttf",
}


def _iter_text_files(root_dir: str):
    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for filename in filenames:
            ext = os.path.splitext(filename)[1].lower()
            if ext in SKIPPED_EXTENSIONS:
                continue
            yield os.path.join(dirpath, filename)


def scan_file(file_path: str, relative_to: str = None):
    """
    Scan a single file and return a list of findings.
    `relative_to` lets us report paths relative to the project root
    instead of an absolute path.
    """
    findings = []
    display_path = (
        os.path.relpath(file_path, relative_to) if relative_to else file_path
    )

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                findings.extend(
                    detect_secrets_in_line(line, line_number, display_path)
                )
                findings.extend(
                    detect_pii_in_line(line, line_number, display_path)
                )
    except (UnicodeDecodeError, PermissionError, OSError):
        # Skip unreadable / binary-ish files rather than crashing the scan.
        pass

    return findings


def scan_directory(root_dir: str):
    """
    Walk root_dir and scan every eligible file.
    Returns a flat list of findings across the whole project.
    """
    all_findings = []
    for file_path in _iter_text_files(root_dir):
        all_findings.extend(scan_file(file_path, relative_to=root_dir))
    return all_findings


def print_findings(findings):
    """Simple human-readable printer, matching the milestone-1 mockup."""
    if not findings:
        print("✅ No findings. Clean scan.")
        return

    for f in findings:
        print(f"❌ Possible {f['type']}")
        print(f"   📍 {f['file']}")
        print(f"   📍 Line {f['line']}")
        print()
