
import { useMemo, useState } from "react";
import "./App.css";
import FindingRow from "./components/FindingRow";
import FindingDetails from "./components/FindingDetails";
import { findings } from "./data/findings";
import type { Finding } from "./data/findings";

function App() {
  const [selectedFinding, setSelectedFinding] =
    useState<Finding | null>(null);

  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] =
    useState("All");

  const filteredFindings = useMemo(() => {
    const query = searchQuery.toLowerCase().trim();

    return findings.filter((finding) => {
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
  }, [searchQuery, severityFilter]);

  const isFiltering =
    searchQuery.trim() !== "" ||
    severityFilter !== "All";

  const displayedFindings = isFiltering
    ? filteredFindings
    : findings.slice(0, 4);

  return (
    <div className="app">
      {/* Left navigation rail */}
      <aside className="sidebar">
        <div className="logo">🛡</div>

        <nav className="nav">
          <button
            className="nav-item active"
            aria-label="Dashboard"
          >
            ⌂
          </button>

          <button
            className="nav-item"
            aria-label="Commits"
          >
            ◈
          </button>

          <button
            className="nav-item"
            aria-label="Findings"
          >
            △
          </button>

          <button
            className="nav-item"
            aria-label="Settings"
          >
            ⚙
          </button>
        </nav>
      </aside>

      {/* Main dashboard */}
      <main className="main-content">
        <header className="header">
          <div>
            <h1>Hi, Aahana</h1>

            <p>
              Here’s your repository security overview.
            </p>
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

        {/* Top dashboard section */}
        <section className="top-section">
          <div className="scan-card">
            <div className="card-header">
              <div>
                <span className="card-label">
                  Latest scan
                </span>

                <h2>Security overview</h2>
              </div>

              <button className="period-button">
                Weekly <span>⌄</span>
              </button>
            </div>

            <div className="scan-summary">
              <div>
                <strong>3</strong>
                <span>Critical</span>
              </div>

              <div className="scan-meta">
                <span>Last scanned</span>
                <strong>Today, 10:42 AM</strong>
              </div>
            </div>

            <div className="mini-chart">
              <span style={{ height: "42%" }} />
              <span style={{ height: "65%" }} />
              <span style={{ height: "35%" }} />
              <span style={{ height: "80%" }} />
              <span style={{ height: "52%" }} />
              <span style={{ height: "92%" }} />
              <span style={{ height: "70%" }} />
            </div>
          </div>

          {/* Stats */}
          <div className="stats-column">
            <div className="stat-tile amber">
              <strong>6</strong>
              <span>Findings</span>
            </div>

            <div className="stat-tile lavender">
              <strong>18</strong>
              <span>Clean files</span>
            </div>

            <div className="stat-tile pink">
              <strong>7</strong>
              <span>Commits scanned</span>
            </div>
          </div>
        </section>

        {/* Risk bar */}
        <section className="risk-section">
          <div className="section-heading">
            <span>Overall risk</span>
            <strong>Medium</strong>
          </div>

          <div className="risk-bar">
            <div className="risk-marker" />
          </div>

          <div className="risk-labels">
            <span>Low</span>
            <span>Moderate</span>
            <span>High</span>
            <span>Critical</span>
          </div>
        </section>

        {/* Recent findings */}
        <section className="findings-section">
          <div className="section-heading findings-heading">
            <div>
              <span>Recent findings</span>

              <p>
                Security issues detected in your repository
              </p>
            </div>

            <button className="view-all">
              View all
            </button>
          </div>

          {/* Severity filters */}
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
                      setSeverityFilter(severity)
                    }
                  >
                    {severity}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Search/filter result summary */}
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

          {/* Findings */}
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
                  ⌕
                </div>

                <strong>
                  No findings found
                </strong>

                <span>
                  Try a different search term or severity
                  filter.
                </span>
              </div>
            )}
          </div>
        </section>
      </main>

      {/* Right utility panel */}
      <aside className="utility-panel">
        <button
          className="close-button"
          aria-label="Close"
        >
          ×
        </button>

        <h2>Action items</h2>

        <p>
          You have 3 unresolved findings
        </p>

        <div className="utility-card">
          <div>□ Rotate credential</div>
          <div>□ Add to .gitignore</div>
          <div>□ Purge from git history</div>
        </div>

        <div className="status-card">
          <strong>✓</strong>

          <span>
            Next scan runs on push
          </span>
        </div>
      </aside>

      {/* Finding details */}
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

export default App;

