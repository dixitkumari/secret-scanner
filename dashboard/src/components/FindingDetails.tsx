import type { Finding } from "../data/findings";

type FindingDetailsProps = {
  finding: Finding;
  onClose: () => void;
};

function FindingDetails({
  finding,
  onClose,
}: FindingDetailsProps) {
  return (
    <div
      className="details-overlay"
      onClick={onClose}
    >
      <div
        className="details-panel"
        onClick={(event) =>
          event.stopPropagation()
        }
      >
        <div className="details-header">
          <div>
            <span className="details-label">
              Security finding
            </span>

            <h2>
              {formatFindingName(finding.type)}
            </h2>
          </div>

          <button
            className="details-close"
            onClick={onClose}
            aria-label="Close finding details"
          >
            ×
          </button>
        </div>

        <div className="details-severity-row">
          <span
            className={`severity ${finding.severity.toLowerCase()}`}
          >
            {finding.severity}
          </span>

          <span className="classification">
            {finding.classification}
          </span>
        </div>

        <div className="confidence">
          <div className="confidence-header">
            <span>Detection confidence</span>

            <strong>
              {finding.confidence !== null
                ? `${Math.round(
                    finding.confidence * 100
                  )}%`
                : "Pending AI"}
            </strong>
          </div>

          <div className="confidence-bar">
            {finding.confidence !== null ? (
              <div
                className="confidence-fill"
                style={{
                  width: `${
                    finding.confidence * 100
                  }%`,
                }}
              />
            ) : (
              <div
                className="confidence-pending"
                style={{
                  width: "35%",
                }}
              />
            )}
          </div>

          <span className="confidence-note">
            {finding.confidence !== null
              ? "Based on the scanner's contextual detection."
              : "AI classification will be added by the AI triage layer."}
          </span>
        </div>

        <div className="detail-grid">
          <div className="detail-item">
            <span>File</span>
            <strong>{finding.file}</strong>
          </div>

          <div className="detail-item">
            <span>Line</span>
            <strong>{finding.line}</strong>
          </div>

          <div className="detail-item">
            <span>Commit</span>
            <strong>{finding.commit}</strong>
          </div>

          <div className="detail-item">
            <span>Author</span>
            <strong>{finding.author}</strong>
          </div>
        </div>

        <div className="detail-section">
          <span>Why was this flagged?</span>

          <p>{finding.reason}</p>
        </div>

        <div className="detail-section action-section">
          <span>Recommended action</span>

          <p>{finding.recommendedAction}</p>
        </div>

        <div className="detail-footer">
          <span>
            Detected on {formatDate(finding.date)}
          </span>

          <button className="remediation-button">
            Start remediation
          </button>
        </div>
      </div>
    </div>
  );
}

function formatFindingName(type: string) {
  return type
    .toLowerCase()
    .split("_")
    .map(
      (word) =>
        word.charAt(0).toUpperCase() +
        word.slice(1)
    )
    .join(" ");
}

function formatDate(date: string) {
  return new Date(date).toLocaleDateString(
    "en-IN",
    {
      day: "numeric",
      month: "short",
      year: "numeric",
    }
  );
}

export default FindingDetails;