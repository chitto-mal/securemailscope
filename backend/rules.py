from __future__ import annotations

RULES_VERSION = "0.1"

SEVERITY_WEIGHT = {
    "critical": 30,
    "high": 20,
    "medium": 10,
    "low": 5,
    "info": 0,
}


def finding(rule_id, severity, title, evidence, remediation):
    return {
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "remediation": remediation,
    }


def evaluate_session(session):
    findings = []

    if session.get("starttls") and not session.get("tls_seen"):
        findings.append(finding(
            "SMTP-STARTTLS-001",
            "medium",
            "STARTTLS transition observed without visible TLS handshake",
            "STARTTLS was visible in the reconstructed mail stream, but no TLS record was observable afterward.",
            "Validate the capture completeness and investigate whether the connection actually transitioned to TLS.",
        ))

    version = session.get("tls_version")
    if version in ("3.0", "3.1", "3.2"):
        findings.append(finding(
            "TLS-VERSION-001",
            "high",
            "Legacy TLS record version observed",
            f"TLS record legacy version {version} was visible in the capture.",
            "Review endpoint configuration and migrate away from obsolete TLS protocol versions.",
        ))

    if session.get("tls_seen") and not session.get("tls_handshake_count"):
        findings.append(finding(
            "TLS-HANDSHAKE-001",
            "medium",
            "TLS records observed but handshake messages were not decoded",
            "TLS framing was visible but no handshake message was decoded from the available evidence.",
            "Capture the complete handshake or inspect whether TCP/TLS fragmentation caused incomplete visibility.",
        ))

    for cert in session.get("certificates", []):
        if cert.get("expired"):
            findings.append(finding(
                "X509-VALIDITY-001",
                "high",
                "Expired certificate observed",
                f"Certificate validity ended at {cert.get('not_valid_after')}.",
                "Replace the expired certificate with a currently valid certificate.",
            ))
        if cert.get("not_yet_valid"):
            findings.append(finding(
                "X509-VALIDITY-002",
                "high",
                "Certificate is not yet valid",
                f"Certificate validity starts at {cert.get('not_valid_before')}.",
                "Check certificate deployment and system clock configuration.",
            ))
        if cert.get("self_signed"):
            findings.append(finding(
                "X509-TRUST-001",
                "medium",
                "Self-signed certificate observed",
                "The captured certificate subject and issuer are identical.",
                "Verify that the certificate is intentionally trusted in the deployment; otherwise use a certificate chain anchored in an appropriate trust store.",
            ))
        if cert.get("public_key_type") == "RSA" and cert.get("public_key_size") and cert["public_key_size"] < 2048:
            findings.append(finding(
                "X509-KEY-001",
                "high",
                "RSA public key below 2048 bits",
                f"Observed RSA public key size: {cert['public_key_size']} bits.",
                "Replace the certificate/key pair with a stronger RSA key or an appropriate modern elliptic-curve key.",
            ))
        if (cert.get("signature_algorithm") or "").lower().startswith("sha1"):
            findings.append(finding(
                "X509-SIG-001",
                "high",
                "SHA-1 certificate signature algorithm observed",
                f"Observed certificate signature hash algorithm: {cert.get('signature_algorithm')}.",
                "Replace the certificate chain with certificates using a modern signature algorithm.",
            ))

    return findings


def evaluate_all(sessions):
    findings = []
    for session in sessions:
        findings.extend({**item, "session": session["id"]} for item in evaluate_session(session))
    return findings
