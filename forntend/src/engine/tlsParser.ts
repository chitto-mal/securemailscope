import type { TLSVersion, X509Certificate, SecurityFinding, SessionFeatureVector } from '../types/pcap';

export interface TlsAnalysisResult {
  version: TLSVersion;
  cipherSuite: string;
  cipherBits: number;
  keyExchange: string;
  forwardSecrecy: boolean;
  certificate?: X509Certificate;
  findings: SecurityFinding[];
}

export function evaluateTlsHandshake(
  version: TLSVersion,
  cipherSuite: string,
  keyExchange: string,
  certificate?: X509Certificate
): TlsAnalysisResult {
  const findings: SecurityFinding[] = [];
  let forwardSecrecy = false;
  let cipherBits = 256;

  // 1. Evaluate TLS Version (RFC 8996 & NIST SP 800-52r2)
  if (version === 'TLS 1.0' || version === 'TLS 1.1') {
    findings.push({
      id: `f-tls-ver-${version.replace(' ', '-').toLowerCase()}`,
      severity: 'HIGH',
      category: 'TLS Protocol',
      title: `Deprecated Protocol Version: ${version}`,
      description: `${version} has been formally deprecated by the IETF in RFC 8996 due to lack of support for modern ciphers and vulnerability to BEAST/POODLE attacks.`,
      impact: 'Allows network eavesdroppers to decrypt traffic or downgrade connection parameters.',
      remediation: 'Disable TLS 1.0 and TLS 1.1 on mail servers; enforce TLS 1.2 minimum (prefer TLS 1.3).',
      complianceRef: 'IETF RFC 8996 & NIST SP 800-52r2 Section 3.1',
    });
  } else if (version === 'None (Plaintext)') {
    findings.push({
      id: 'f-tls-none',
      severity: 'CRITICAL',
      category: 'TLS Protocol',
      title: 'Unencrypted Session (Plaintext)',
      description: 'Session communicated without any TLS encryption wrapper.',
      impact: 'All credentials, authentication tokens, and email bodies visible in cleartext.',
      remediation: 'Configure mail client and MTA to reject unencrypted plaintext mail sessions.',
      complianceRef: 'NIST SP 800-52r2 & CIS Benchmark',
    });
  }

  // 2. Cipher Suite & Key Exchange Evaluation
  const upperCipher = cipherSuite.toUpperCase();
  if (upperCipher.includes('ECDHE') || upperCipher.includes('DHE')) {
    forwardSecrecy = true;
  }

  if (upperCipher.includes('RC4')) {
    cipherBits = 128;
    findings.push({
      id: 'f-cipher-rc4',
      severity: 'CRITICAL',
      category: 'Cipher Suite',
      title: 'Insecure Stream Cipher: RC4 Negotiated',
      description: 'RC4 cipher suite negotiated. RC4 suffers from severe keystream biases allowing plaintext recovery.',
      impact: 'Session key recovery and plaintext mail interception by passive network observer.',
      remediation: 'Immediately remove all RC4 cipher suites from server TLS configuration per RFC 7465.',
      complianceRef: 'IETF RFC 7465 & NIST SP 800-52r2 Section 3.3.1',
    });
  } else if (upperCipher.includes('3DES') || upperCipher.includes('DES-CBC3')) {
    cipherBits = 112;
    findings.push({
      id: 'f-cipher-3des',
      severity: 'HIGH',
      category: 'Cipher Suite',
      title: 'Vulnerable Block Cipher: 3DES (Sweet32)',
      description: '3DES features 64-bit block sizes vulnerable to birthday attack collisions (Sweet32 attack / CVE-2016-2183).',
      impact: 'Long-running sessions subject to plaintext recovery attacks.',
      remediation: 'Disable 3DES and DES ciphers. Require AES-128-GCM, AES-256-GCM, or ChaCha20-Poly1305.',
      complianceRef: 'NIST SP 800-52r2 & CVE-2016-2183',
    });
  }

  if (!forwardSecrecy && version !== 'None (Plaintext)') {
    findings.push({
      id: 'f-no-pfs',
      severity: 'MEDIUM',
      category: 'Forward Secrecy',
      title: 'Missing Perfect Forward Secrecy (PFS)',
      description: `Static ${keyExchange} key exchange negotiated without ephemeral Diffie-Hellman (ECDHE/DHE).`,
      impact: 'If the server RSA private key is compromised in the future, all past recorded session captures can be retroactively decrypted.',
      remediation: 'Prioritize ECDHE key exchange suites (e.g. TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384).',
      complianceRef: 'NIST SP 800-52r2 Section 3.3.2',
    });
  }

  // 3. Certificate Evaluation
  if (certificate) {
    if (certificate.isExpired) {
      findings.push({
        id: 'f-cert-expired',
        severity: 'CRITICAL',
        category: 'Certificate',
        title: 'Expired X.509 Server Certificate',
        description: `The mail server certificate expired ${Math.abs(certificate.daysToExpiry)} days ago on ${certificate.validTo}.`,
        impact: 'Breaks chain of trust; exposes users to active man-in-the-middle impersonation attacks.',
        remediation: 'Renew X.509 certificate immediately via trusted Certificate Authority (CA) or ACME/Let\'s Encrypt.',
        complianceRef: 'RFC 5280 Section 4.1.2.5',
      });
    }

    if (certificate.keyType === 'RSA' && certificate.keyLength < 2048) {
      findings.push({
        id: 'f-cert-weak-rsa',
        severity: 'HIGH',
        category: 'Certificate',
        title: 'Weak RSA Certificate Key Length',
        description: `RSA key length is ${certificate.keyLength}-bit (below NIST recommended 2048-bit minimum).`,
        impact: 'RSA 1024-bit keys are computationally vulnerable to factorization by state-level adversaries.',
        remediation: 'Re-issue certificate with RSA key size ≥ 2048-bit or ECDSA P-256 / P-384 curve.',
        complianceRef: 'NIST SP 800-57 Part 1 Revision 5',
      });
    }

    if (certificate.signatureAlgorithm === 'MD5withRSA' || certificate.signatureAlgorithm === 'SHA1withRSA') {
      findings.push({
        id: 'f-cert-weak-sig',
        severity: 'HIGH',
        category: 'Certificate',
        title: `Deprecated Certificate Signature Hash: ${certificate.signatureAlgorithm}`,
        description: `Certificate signed using ${certificate.signatureAlgorithm}, which suffers from collision attacks.`,
        impact: 'Attacker could forge valid-looking certificates with colliding MD5/SHA-1 signatures.',
        remediation: 'Re-issue certificate using SHA-256 or SHA-384 signature digest algorithm.',
        complianceRef: 'CAB Forum Baseline Requirements Section 7.1.3',
      });
    }

    if (certificate.isSelfSigned) {
      findings.push({
        id: 'f-cert-self-signed',
        severity: 'MEDIUM',
        category: 'Certificate',
        title: 'Self-Signed Certificate Detected',
        description: 'Certificate was signed by itself rather than a recognized publicly trusted Root CA.',
        impact: 'Mail clients cannot verify identity automatically; risks domain spoofing.',
        remediation: 'Replace self-signed certificates with certificates signed by an audited public or enterprise PKI CA.',
        complianceRef: 'NIST SP 800-52r2 Section 3.2',
      });
    }
  }

  return {
    version,
    cipherSuite,
    cipherBits,
    keyExchange,
    forwardSecrecy,
    certificate,
    findings,
  };
}

export function extractFeatureVector(
  version: TLSVersion,
  cipherSuite: string,
  cipherBits: number,
  forwardSecrecy: boolean,
  certificate?: X509Certificate,
  starttlsUsed: boolean = true,
  starttlsAnomaly: boolean = false
): SessionFeatureVector {
  return {
    tlsVersion: version,
    cipherSuite,
    cipherBits,
    forwardSecrecy,
    certKeyLength: certificate ? certificate.keyLength : 0,
    certIsExpired: certificate ? certificate.isExpired : false,
    certIsSelfSigned: certificate ? certificate.isSelfSigned : false,
    certSigAlgoWeak: certificate ? (certificate.signatureAlgorithm === 'MD5withRSA' || certificate.signatureAlgorithm === 'SHA1withRSA') : false,
    starttlsUsed,
    starttlsAnomalyFlag: starttlsAnomaly,
    handshakeRttMs: Math.floor(15 + Math.random() * 35),
    sessionResumption: false,
  };
}
