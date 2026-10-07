// The grader's findings. The backend sorts them: critical, then warning, then info.

const LABELS = { critical: "Critical", warning: "Warning", info: "Info" };

export default function Findings({ findings }) {
  return (
    <section className="card">
      <h3 className="section-title">Findings</h3>
      {findings.length === 0 ? (
        <p className="muted">Nothing to fix: this setup does everything the grader checks for.</p>
      ) : (
        <ul className="findings">
          {findings.map((f, i) => (
            <li key={i} className={`finding finding-${f.severity}`}>
              <span className={`tag tag-${f.severity}`}>{LABELS[f.severity] ?? f.severity}</span>
              <span>{f.message}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
