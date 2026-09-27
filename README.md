# Git Scanner + Secret Detection (Dixit's module)

Finds suspicious secrets/PII in a codebase, and identifies which Git
commit introduced them.

## Setup

```bash
git clone <your-team-repo-url>
cd <repo-name>
git checkout -b dixit-scanner

# copy these files into the repo, then:
pip install -r requirements.txt
```

## Usage

Plain file scan (no Git awareness) — Milestones 1-2:

```bash
python main.py scan-files sample_project
python main.py scan-files sample_project --json
```

Git-aware scan — Milestones 3-4, finds which commit introduced each finding:

```bash
python main.py scan-git /path/to/some/repo
python main.py scan-git /path/to/some/repo --json
```

Run tests:

```bash
pip install pytest
python -m pytest tests/
```

## What's implemented

- `scanner/secret_detector.py` — AWS keys, generic API keys/tokens,
  private key blocks, hardcoded passwords, DB connection strings with
  embedded credentials. Filters out obvious placeholders
  (`changeme`, `your-key-here`, etc.) to cut noise.
- `scanner/pii_detector.py` — emails, PAN numbers, and Aadhaar numbers.
  Aadhaar detection is context-aware: a bare 12-digit number is only
  flagged as high-confidence `AADHAAR` if the filename or line contains
  a hint like "aadhaar"; otherwise it's reported as low-confidence
  `POSSIBLE_AADHAAR` so nothing is silently dropped, but noise is
  clearly separated from real risk.
- `scanner/file_scanner.py` — walks a directory tree, runs both
  detectors against every text file, skips `.git`/`node_modules`/binary
  files.
- `scanner/git_scanner.py` — uses GitPython to diff each commit against
  its parent, extract only the *added* lines, and run the same
  detectors against just those lines. Tags each finding with the
  commit hash, author, and date.
- `main.py` — CLI wrapper for both scan modes, with `--json` for
  structured output.
- `tests/test_detectors.py` — sanity tests for the regex/context logic.

## Known limitation to fix next

CSV header context isn't used yet — if a file has a header row like
`name,email,pan,aadhaar` and the Aadhaar number is on a *different* line
(the data row), the context check currently only looks at the data
line itself, not the header. Right now that falls back to the
low-confidence `POSSIBLE_AADHAAR` label instead of a firm `AADHAAR`
flag. Fix: for `.csv` files, parse the header row once and pass matching
column context down to the per-line detector.

## Output schema (for Jiya's AI layer)

```json
{
  "type": "AWS_ACCESS_KEY",
  "file": ".env",
  "line": 4,
  "value": "AKIA****************",
  "context": "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP",
  "commit": "a82f91c",
  "author": "Developer Name",
  "date": "2026-09-20T10:15:00+05:30"
}
```

`commit`, `author`, `date` are only present when using `scan-git`
(plain `scan-files` findings won't have them).

## Next: building the demo repo (Step 6)

Create a small separate repo with 3 commits:

1. README + normal code → clean
2. `.env` with a **fake** AWS-looking key + `customers.csv` with fake emails → findings
3. `test_data.csv` with dummy values → low risk

Never use a real key or a real person's PAN/Aadhaar in this repo.
