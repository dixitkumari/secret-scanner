"""
main.py

CLI entry point.

Usage:
    python main.py scan-files <path>          # Milestone 1-2: plain file scan
    python main.py scan-git <repo_path>        # Milestone 3-4: git-aware scan
    python main.py scan-git <repo_path> --json  # Milestone 5: structured JSON
    python main.py scan-files <path> --json
"""

import json
import sys


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    command = sys.argv[1]
    target_path = sys.argv[2]
    as_json = "--json" in sys.argv

    if command == "scan-files":
        # Imported here (not at the top of the file) so this command
        # works even if GitPython/git isn't installed correctly yet.
        from scanner.file_scanner import scan_directory, print_findings
        findings = scan_directory(target_path)
        if as_json:
            print(json.dumps(findings, indent=2))
        else:
            print_findings(findings)

    elif command == "scan-git":
        from scanner.git_scanner import scan_repository, print_commit_findings
        findings = scan_repository(target_path)
        if as_json:
            print(json.dumps(findings, indent=2))
        else:
            print_commit_findings(findings)

    else:
        print(f"Unknown command: {command}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
