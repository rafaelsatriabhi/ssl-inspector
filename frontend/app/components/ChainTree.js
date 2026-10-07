// The certificate chain as the server sent it, leaf first: Leaf → Intermediate → Root.
// Each certificate is issued (signed) by the one below it.

import { certWarnings } from "@/lib/certWarnings";

const ROLE_LABELS = { leaf: "Leaf", intermediate: "Intermediate", root: "Root" };
const SAN_PREVIEW = 6;

function formatDate(iso) {
  return new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

function keyLabel(cert) {
  return cert.key_size ? `${cert.key_type}, ${cert.key_size} bits` : cert.key_type;
}

function CertNode({ cert }) {
  const warnings = certWarnings(cert);
  const hasCritical = warnings.some((w) => w.severity === "critical");
  const name = cert.common_name ?? cert.subject;

  return (
    <li className="chain-item">
      <article className={`cert ${hasCritical ? "cert-bad" : warnings.length ? "cert-warn" : ""}`}>
        <header className="cert-header">
          <span className={`role role-${cert.role}`}>{ROLE_LABELS[cert.role] ?? cert.role}</span>
          <h4 className="cert-name">{name}</h4>
        </header>

        <dl className="cert-facts">
          <div>
            <dt>Issued by</dt>
            <dd>{cert.self_signed ? "Itself (self-signed)" : (cert.issuer_common_name ?? cert.issuer)}</dd>
          </div>
          <div>
            <dt>Valid until</dt>
            <dd>
              {formatDate(cert.not_after)}{" "}
              <span className={cert.days_remaining < 0 ? "text-bad" : cert.days_remaining <= 30 ? "text-warn" : "muted"}>
                ({cert.days_remaining < 0 ? `${-cert.days_remaining} days ago` : `${cert.days_remaining} days left`})
              </span>
            </dd>
          </div>
          <div>
            <dt>Key</dt>
            <dd>{keyLabel(cert)}</dd>
          </div>
          <div>
            <dt>Signature</dt>
            <dd className="mono">{cert.signature_algorithm}</dd>
          </div>
        </dl>

        {warnings.length > 0 && (
          <ul className="cert-warnings">
            {warnings.map((w) => (
              <li key={w.text} className={`cert-warning cert-warning-${w.severity}`}>
                {w.text}
              </li>
            ))}
          </ul>
        )}

        <details className="cert-details">
          <summary>All details</summary>
          <dl className="detail-list">
            <dt>Subject</dt>
            <dd className="mono">{cert.subject}</dd>
            <dt>Issuer</dt>
            <dd className="mono">{cert.issuer}</dd>
            <dt>Valid from</dt>
            <dd>{new Date(cert.not_before).toUTCString()}</dd>
            <dt>Valid until</dt>
            <dd>{new Date(cert.not_after).toUTCString()}</dd>
            <dt>Serial number</dt>
            <dd className="mono break">{cert.serial_number}</dd>
            <dt>SHA-256 fingerprint</dt>
            <dd className="mono break">{cert.sha256_fingerprint}</dd>
            <dt>CA certificate</dt>
            <dd>{cert.is_ca ? "Yes" : "No"}</dd>
            {cert.sans.length > 0 && (
              <>
                <dt>Subject Alternative Names ({cert.sans.length})</dt>
                <dd>
                  <SanList sans={cert.sans} />
                </dd>
              </>
            )}
          </dl>
        </details>
      </article>
    </li>
  );
}

function SanList({ sans }) {
  const shown = sans.slice(0, SAN_PREVIEW);
  const rest = sans.slice(SAN_PREVIEW);
  return (
    <ul className="sans">
      {shown.map((s) => (
        <li key={s} className="mono">{s}</li>
      ))}
      {rest.length > 0 && (
        <li>
          <details>
            <summary>{rest.length} more</summary>
            <ul className="sans">
              {rest.map((s) => (
                <li key={s} className="mono">{s}</li>
              ))}
            </ul>
          </details>
        </li>
      )}
    </ul>
  );
}

export default function ChainTree({ report }) {
  const { chain, trusted } = report;
  const last = chain[chain.length - 1];
  // Servers usually leave out the root: the client must already have it, so sending it wastes bytes.
  const rootOmitted = last && last.role !== "root";

  return (
    <section className="card">
      <h3 className="section-title">Certificate chain</h3>
      {chain.length === 0 ? (
        <p className="muted">The server did not present any certificates.</p>
      ) : (
        <ol className="chain">
          {chain.map((cert) => (
            <CertNode key={cert.sha256_fingerprint} cert={cert} />
          ))}
          {rootOmitted && (
            <li className="chain-item">
              <div className={`anchor ${trusted ? "anchor-ok" : "anchor-bad"}`}>
                {trusted
                  ? `The chain ends at a root in the system trust store. The server didn't send it, which is normal.`
                  : `No trusted root found above ${last.common_name ?? "the last certificate"}.`}
              </div>
            </li>
          )}
        </ol>
      )}
    </section>
  );
}
