"""
git_scanner.py

Milestone 3 + 4: use GitPython to look at commits, find the lines that
were *added* in each commit (not the whole file every time), and run
the same secret/PII detectors against just those new lines.

This is what lets us report "commit a82f91c introduced this AWS key"
instead of just "this file currently contains an AWS key somewhere".
"""

from git import Repo

from scanner.secret_detector import detect_secrets_in_line
from scanner.pii_detector import detect_pii_in_line


def _run_detectors(line: str, line_number: int, file_path: str):
    findings = detect_secrets_in_line(line, line_number, file_path)
    findings.extend(detect_pii_in_line(line, line_number, file_path))
    return findings


def _added_lines_for_diff(diff):
    """
    Given a git diff for one changed file in one commit, yield
    (line_number_in_new_file, line_text) for every added line.

    Uses the unified diff text and tracks the new-file line counter
    from the @@ -a,b +c,d @@ hunk headers.
    """
    if diff.diff is None:
        return

    try:
        diff_text = diff.diff.decode("utf-8", errors="ignore")
    except AttributeError:
        diff_text = str(diff.diff)

    new_line_number = 0
    for raw_line in diff_text.splitlines():
        if raw_line.startswith("@@"):
            # Example: @@ -12,7 +12,9 @@
            try:
                plus_part = raw_line.split("+")[1].split(" ")[0]
                new_line_number = int(plus_part.split(",")[0]) - 1
            except (IndexError, ValueError):
                new_line_number = 0
            continue

        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            new_line_number += 1
            yield new_line_number, raw_line[1:]
        elif raw_line.startswith("-") and not raw_line.startswith("---"):
            continue
        else:
            new_line_number += 1


def scan_commit(repo: Repo, commit):
    """
    Scan a single commit's added lines for secrets/PII.
    Returns a list of findings, each tagged with commit + author info.
    """
    findings = []

    parents = commit.parents
    if not parents:
        # Initial commit: diff against an empty tree so everything counts
        # as "added".
        diffs = commit.diff(None, create_patch=True)
    else:
        diffs = parents[0].diff(commit, create_patch=True)

    for diff in diffs:
        file_path = diff.b_path or diff.a_path
        if file_path is None:
            continue

        for line_number, line_text in _added_lines_for_diff(diff):
            line_findings = _run_detectors(line_text, line_number, file_path)
            for lf in line_findings:
                lf["commit"] = commit.hexsha[:7]
                lf["author"] = str(commit.author)
                lf["date"] = commit.committed_datetime.isoformat()
                findings.append(lf)

    return findings


def scan_repository(repo_path: str, max_commits: int = 50):
    """
    Walk the most recent `max_commits` commits (newest first) and
    collect findings introduced in each one.
    """
    repo = Repo(repo_path)
    all_findings = []

    commits = list(repo.iter_commits(max_count=max_commits))
    for commit in commits:
        all_findings.extend(scan_commit(repo, commit))

    return all_findings


def print_commit_findings(findings):
    """Human-readable printer matching the milestone-3 mockup."""
    if not findings:
        print("✅ No findings across scanned commits.")
        return

    for f in findings:
        print(f"Commit: {f['commit']}")
        print(f"Author: {f['author']}")
        print(f"File: {f['file']}")
        print(f"Type: {f['type']}")
        print(f"Added line: {f['context']}")
        print()
