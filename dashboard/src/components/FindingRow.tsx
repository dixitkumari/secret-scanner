import type { Finding } from "../data/findings";

type FindingRowProps = {
  finding: Finding;
};

function FindingRow({ finding }: FindingRowProps) {
  const getIcon = () => {
    if (finding.type.includes("KEY")) return "🔑";
    if (finding.type.includes("EMAIL")) return "✉";
    if (finding.type.includes("AADHAAR")) return "#";
    return "!";
  };

  const severityClass = finding.severity.toLowerCase();

  return (
    <div className="finding-row">
      <div className="finding-icon">
        {getIcon()}
      </div>

      <div className="finding-info">
        <strong>{formatFindingName(finding.type)}</strong>

        <span>
          {finding.file} · Line {finding.line} · Commit {finding.commit}
        </span>
      </div>

      <span className={`severity ${severityClass}`}>
        {finding.severity}
      </span>
    </div>
  );
}

function formatFindingName(type: string) {
  return type
    .toLowerCase()
    .split("_")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

export default FindingRow;