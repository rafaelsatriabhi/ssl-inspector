// Grade badge plus the connection facts: host, IP, trust, protocol, cipher.

function gradeClass(grade) {
  if (grade.startsWith("A")) return "grade-a";
  if (grade === "B") return "grade-b";
  if (grade === "C") return "grade-c";
  if (grade === "D") return "grade-d";
  return "grade-f";
}

// Same thresholds as _score_to_grade() in backend/app/grading.py.
function gradeForScore(score) {
  if (score >= 95) return "A+";
  if (score >= 85) return "A";
  if (score >= 70) return "B";
  if (score >= 50) return "C";
  if (score >= 35) return "D";
  return "F";
}

export default function ReportSummary({ report }) {
  // Some findings cap the grade instead of costing points (e.g. expired → F, any warning → no A+).
  const capped = report.grade !== gradeForScore(report.score);
  const legacy = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"].includes(report.tls_version);

  return (
    <section className="summary card">
      <div className={`grade ${gradeClass(report.grade)}`} aria-label={`Grade ${report.grade}`}>
        <span className="grade-letter">{report.grade}</span>
        <span className="grade-score">{report.score}/100</span>
      </div>

      <div className="summary-body">
        <h2 className="summary-host">
          {report.host}
          {report.port !== 443 && <span className="muted">:{report.port}</span>}
        </h2>

        <dl className="facts">
          <div>
            <dt>Trust</dt>
            <dd>
              {report.trusted ? (
                <span className="pill pill-ok">Trusted</span>
              ) : (
                <span className="pill pill-bad" title={report.verify_error ?? undefined}>
                  Not trusted
                </span>
              )}
            </dd>
          </div>
          <div>
            <dt>IP address</dt>
            <dd className="mono">{report.ip}</dd>
          </div>
          <div>
            <dt>Protocol</dt>
            <dd className={legacy ? "text-bad" : undefined}>{report.tls_version ?? "unknown"}</dd>
          </div>
          <div>
            <dt>Cipher suite</dt>
            <dd className="mono">
              {report.cipher ?? "unknown"}
              {report.cipher_bits != null && <span className="muted"> ({report.cipher_bits}-bit)</span>}
            </dd>
          </div>
        </dl>

        {capped && (
          <p className="cap-note muted">
            The points alone would earn {gradeForScore(report.score)}, but the findings below cap the grade at{" "}
            {report.grade}.
          </p>
        )}

        {!report.trusted && report.verify_error && (
          <p className="verify-error">{report.verify_error}</p>
        )}
      </div>
    </section>
  );
}
