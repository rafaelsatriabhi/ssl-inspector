// Per-certificate problems shown on each node of the chain tree.
// These follow the rules in backend/app/grading.py. The backend reports its findings
// for the whole connection; this repeats the checks so each one shows on the certificate it's about.

const WEAK_HASHES = ["md5", "sha1"];

export function certWarnings(cert) {
  const warnings = [];
  const critical = (text) => warnings.push({ severity: "critical", text });
  const warning = (text) => warnings.push({ severity: "warning", text });

  if (cert.days_remaining < 0) {
    critical(`Expired ${-cert.days_remaining} days ago`);
  } else if (cert.days_remaining <= 30) {
    warning(`Expires in ${cert.days_remaining} days`);
  }
  if (new Date(cert.not_before) > new Date()) {
    critical("Not valid yet");
  }
  // A root's self-signature is never checked, so its hash doesn't matter.
  if (cert.role !== "root" && WEAK_HASHES.includes(cert.signature_hash)) {
    critical(`Signed with weak hash ${cert.signature_hash.toUpperCase()}`);
  }
  if (cert.key_type === "RSA" && cert.key_size && cert.key_size < 2048) {
    critical(`Weak ${cert.key_size}-bit RSA key`);
  }
  if (cert.role === "leaf") {
    if (cert.self_signed) critical("Self-signed: no CA vouches for this certificate");
    if (cert.sans.length === 0) warning("No Subject Alternative Names");
  }
  return warnings;
}
