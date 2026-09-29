import { useMemo, useState } from "react";
import "./App.css";
import FindingRow from "./components/FindingRow";
import FindingDetails from "./components/FindingDetails";
import type { Finding, Severity } from "./data/findings";

type ScanSummary = {
  findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  commitsScanned: number;
  filesScanned: number;
};

type ScanResponse = {
  findings: Finding[];
  summary: ScanSummary;
  scannedAt: string;
};

const emptySummary: ScanSummary = {
  findings: 0,
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  commitsScanned: 0,
  filesScanned: 0,
};

function App() {
  const [selectedFinding, setSelectedFinding] =
    useState<Finding | null>(null);

  const [searchQuery, setSearchQuery] = useState("");

  const [severityFilter, setSeverityFilter] =
    useState<"All" | Severity>("All");

  const [currentFindings, setCurrentFindings] =
    useState<Finding[]>([]);

  const [summary, setSummary] =
    useState<ScanSummary>(emptySummary);

  const [scannedAt, setScannedAt] =
    useState<string | null>(null);

  const [isScanning, setIsScanning] =
    useState(false);

  const [scanError, setScanError] =
    useState("");

  const filteredFindings = useMemo(() => {
    const query = searchQuery.toLowerCase().trim();

    return currentFindings.filter((finding) => {
      const matchesSearch =
        query === "" ||
        finding.type.toLowerCase().includes(query) ||
        finding.file.toLowerCase().includes(query) ||
        finding.commit.toLowerCase().includes(query) ||
        finding.author.toLowerCase().includes(query) ||
        finding.classification
          .toLowerCase()
          .includes(query);

      const matchesSeverity =
        severityFilter === "All" ||
        finding.severity.toLowerCase() ===
          severityFilter.toLowerCase();

      return matchesSearch && matchesSeverity;
    });
  }, [
    currentFindings,
    searchQuery,
    severityFilter,
  ]);

  const isFiltering =
    searchQuery.trim() !== "" ||
    severityFilter !== "All";

  const displayedFindings = isFiltering
    ? filteredFindings
    : currentFindings.slice(0, 4);

  const overallRisk = getOverallRisk(summary);

  async function handleScan() {
    setIsScanning(true);
    setScanError("");

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data?.message ||
            data?.error ||
            "The repository scan failed."
        );
      }

      const result = data as ScanResponse;

      setCurrentFindings(result.findings);
      setSummary(result.summary);
      setScannedAt(result.scannedAt);
      setSelectedFinding(null);
      setSearchQuery("");
      setSeverityFilter("All");
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "Unable to connect to the scanner.";

      setScanError(
        `${message} Make sure the SentinelGit API is running.`
      );
    } finally {
      setIsScanning(false);
    }
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="logo">🛡</div>

        <nav className="nav">
          <button className="nav-item active" aria-label="Dashboard">
            ⌂
          </button>

          <button className="nav-item" aria-label="Commits">
            ◈
          </button>

          <button className="nav-item" aria-label="Findings">
            △
          </button>

          <button className="nav-item" aria-label="Settings">
            ⚙
          </button>
        </nav>
      </aside>

      <main className="main-content">
        <header className="header">
          <div>
            <h1>Hi, Aahana</h1>
            <p>Here’s your repository security overview.</p>
          </div>

          <div className="header-actions">
            <div className="search">
              <span>⌕</span>

              <input
                type="text"
                value={searchQuery}
                onChange={(event) =>
                  setSearchQuery(event.target.value)
                }
                placeholder="Search findings..."
                aria-label="Search findings"
              />
            </div>

            <button
              className="notification"
              aria-label="Notifications"
            >
              ♢
            </button>
          </div>
        </header>

        <section className="top-section">
          <div className="scan-card">
            <div className="card-header">
              <div>
                <span className="card-label">
                  Latest scan
                </span>

                <h2>Security overview</h2>
              </div>

              <button
                className="period-button scan-button"
                onClick={handleScan}
                disabled={isScanning}
              >
                {isScanning
                  ? "Scanning..."
                  : "Scan repository"}
              </button>
            </div>

            <div className="scan-summary">
              <div>
                <strong>{summary.critical}</strong>
                <span>Critical</span>
              </div>

              <div className="scan-meta">
                <span>Last scanned</span>

                <strong>
                  {scannedAt
                    ? formatScanDate(scannedAt)
                    : "Not scanned yet"}
                </strong>
              </div>
            </div>

            <div className="mini-chart">
              <span
                style={{
                  height: `${getChartHeight(
                    summary.low
                  )}%`,
                }}
              />

              <span
                style={{
                  height: `${getChartHeight(
                    summary.medium
                  )}%`,
                }}
              />

              <span
                style={{
                  height: `${getChartHeight(
                    summary.high
                  )}%`,
                }}
              />

              <span
                style={{
                  height: `${getChartHeight(
                    summary.critical
                  )}%`,
                }}
              />

              <span
                style={{
                  height: `${getChartHeight(
                    summary.findings
                  )}%`,
                }}
              />

              <span
                style={{
                  height: `${getChartHeight(
                    summary.commitsScanned
                  )}%`,
                }}
              />

              <span
                style={{
                  height: `${getChartHeight(
                    summary.filesScanned
                  )}%`,
                }}
              />
            </div>
          </div>

          <div className="stats-column">
            <div className="stat-tile amber">
              <strong>{summary.findings}</strong>
              <span>Findings</span>
            </div>

            <div className="stat-tile lavender">
              <strong>{summary.filesScanned}</strong>
              <span>Files scanned</span>
            </div>

            <div className="stat-tile pink">
              <strong>{summary.commitsScanned}</strong>
              <span>Commits scanned</span>
            </div>
          </div>
        </section>

        {scanError && (
          <div className="scan-error">
            <strong>Scan failed</strong>
            <span>{scanError}</span>
          </div>
        )}

        <section className="risk-section">
          <div className="section-heading">
            <span>Overall risk</span>
            <strong>{overallRisk}</strong>
          </div>

          <div className="risk-bar">
            <div
              className="risk-marker"
              style={{
                left: `${getRiskPosition(
                  overallRisk
                )}%`,
              }}
            />
          </div>

          <div className="risk-labels">
            <span>Low</span>
            <span>Moderate</span>
            <span>High</span>
            <span>Critical</span>
          </div>
        </section>

        <section className="findings-section">
          <div className="section-heading findings-heading">
            <div>
              <span>Recent findings</span>
              <p>
                Security issues detected in your repository
              </p>
            </div>

            <button
              className="view-all"
              onClick={() => {
                setSearchQuery("");
                setSeverityFilter("All");
              }}
            >
              View all
            </button>
          </div>

          <div className="finding-controls">
            <div className="filter-label">
              Filter by severity:
            </div>

            <div className="filter-buttons">
              {[
                "All",
                "Critical",
                "High",
                "Medium",
                "Low",
              ].map((severity) => {
                const isActive =
                  severityFilter === severity;

                return (
                  <button
                    key={severity}
                    className={
                      isActive
                        ? "filter-button active"
                        : "filter-button"
                    }
                    onClick={() =>
                      setSeverityFilter(
                        severity as
                          | "All"
                          | Severity
                      )
                    }
                  >
                    {severity}
                  </button>
                );
              })}
            </div>
          </div>

          {isFiltering && (
            <div className="results-summary">
              <span>
                Showing{" "}
                <strong>
                  {displayedFindings.length}
                </strong>{" "}
                finding
                {displayedFindings.length !== 1
                  ? "s"
                  : ""}
              </span>

              {searchQuery.trim() !== "" && (
                <span>
                  for "
                  <strong>{searchQuery}</strong>"
                </span>
              )}
            </div>
          )}

          <div className="finding-list">
            {displayedFindings.length > 0 ? (
              displayedFindings.map((finding) => (
                <div
                  key={finding.id}
                  className="finding-clickable"
                  role="button"
                  tabIndex={0}
                  onClick={() =>
                    setSelectedFinding(finding)
                  }
                  onKeyDown={(event) => {
                    if (
                      event.key === "Enter" ||
                      event.key === " "
                    ) {
                      event.preventDefault();
                      setSelectedFinding(finding);
                    }
                  }}
                >
                  <FindingRow finding={finding} />
                </div>
              ))
            ) : (
              <div className="empty-state">
                <div className="empty-icon">
                  {isScanning ? "↻" : "⌕"}
                </div>

                <strong>
                  {isScanning
                    ? "Scanning repository..."
                    : "No findings yet"}
                </strong>

                <span>
                  {isScanning
                    ? "SentinelGit is checking recent Git commits."
                    : "Run a repository scan to load real security findings."}
                </span>
              </div>
            )}
          </div>
        </section>
      </main>

      <aside className="utility-panel">
        <button
          className="close-button"
          aria-label="Close"
        >
          ×
        </button>

        <h2>Action items</h2>

        <p>
          You have{" "}
          {getUnresolvedCount(summary)} unresolved finding
          {getUnresolvedCount(summary) !== 1
            ? "s"
            : ""}
        </p>

        <div className="utility-card">
          <div>□ Rotate credential</div>
          <div>□ Add to .gitignore</div>
          <div>□ Purge from git history</div>
        </div>

        <div className="status-card">
          <strong>✓</strong>
          <span>
            Scanner connected to repository
          </span>
        </div>
      </aside>

      {selectedFinding && (
        <FindingDetails
          finding={selectedFinding}
          onClose={() =>
            setSelectedFinding(null)
          }
        />
      )}
    </div>
  );
}

function formatScanDate(date: string) {
  return new Date(date).toLocaleString("en-IN", {
    day: "numeric",
    month: "short",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

function getChartHeight(value: number) {
  if (value <= 0) return 18;

  return Math.min(
    95,
    Math.max(25, value * 10)
  );
}

function getOverallRisk(summary: ScanSummary) {
  if (summary.critical > 0) return "Critical";
  if (summary.high > 0) return "High";
  if (summary.medium > 0) return "Medium";
  if (summary.low > 0) return "Low";

  return "Low";
}

function getRiskPosition(risk: string) {
  switch (risk) {
    case "Critical":
      return 90;

    case "High":
      return 72;

    case "Medium":
      return 55;

    default:
      return 25;
  }
}

function getUnresolvedCount(
  summary: ScanSummary
) {
  return (
    summary.critical +
    summary.high +
    summary.medium
  );
}

export default App;