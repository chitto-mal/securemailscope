import type { ForensicPcapDataset } from '../types/pcap';
import { evaluateTlsHandshake, extractFeatureVector } from '../engine/tlsParser';
import { analyzeStarttlsStateMachine } from '../engine/starttlsStateMachine';
import { calculateSessionRiskScore, computeSecurityPostureSummary } from '../engine/riskFusionEngine';

// Build Synthetic Dataset 1: Legacy Vulnerable Infrastructure
const s1_starttls = analyzeStarttlsStateMachine('SMTP', 25, [
  '220 mail.legacy-gov.in ESMTP Postfix (Ubuntu)',
  'EHLO client.internal.net',
  '220-STARTTLS',
  '220 2.0.0 Ready to start TLS',
  'STARTTLS',
  'NOOP', // Injected command
  'AUTHENTICATE PLAIN', // Injected command
  '220 2.0.0 Go ahead with TLS',
]);

const s1_tls = evaluateTlsHandshake('TLS 1.0', 'SSL_RSA_WITH_RC4_128_SHA', 'RSA-1024', {
  subject: 'CN=mail.legacy-gov.in, O=State Mail Service, C=IN',
  issuer: 'CN=Legacy Internal CA, O=State Gov',
  validFrom: '2021-01-01',
  validTo: '2023-01-01',
  daysToExpiry: -1345,
  isExpired: true,
  keyType: 'RSA',
  keyLength: 1024,
  signatureAlgorithm: 'MD5withRSA',
  isSelfSigned: true,
  sanMatch: true,
  serialNumber: '0x8849A1F290C',
});

const s1_findings = [...s1_starttls.findings, ...s1_tls.findings];
const s1_aiScore = 0.88;
const s1_risk = calculateSessionRiskScore(s1_findings, s1_aiScore);

const session1 = {
  id: 'sess-001',
  pcapFile: 'legacy-vulnerable-mail.pcap',
  timestamp: '2026-09-08 14:10:22.045',
  srcIp: '192.168.4.120',
  srcPort: 49204,
  dstIp: '10.20.5.15',
  dstPort: 25,
  serverHostname: 'mail.legacy-gov.in',
  protocol: 'SMTP' as const,
  tlsVersion: s1_tls.version,
  cipherSuite: s1_tls.cipherSuite,
  keyExchange: s1_tls.keyExchange,
  forwardSecrecy: s1_tls.forwardSecrecy,
  starttlsState: s1_starttls.state,
  certificate: s1_tls.certificate,
  milestones: s1_starttls.milestones,
  featureVector: extractFeatureVector(s1_tls.version, s1_tls.cipherSuite, s1_tls.cipherBits, s1_tls.forwardSecrecy, s1_tls.certificate, true, true),
  findings: s1_findings,
  riskScore: s1_risk.score,
  riskTier: s1_risk.tier,
  aiAnomalyScore: s1_aiScore,
  aiExplanation: 'Flagged by Isolation Forest: High statistical anomaly vector (RC4 cipher + TLS 1.0 + unencrypted NOOP/AUTH injected commands in STARTTLS buffer).',
  rawHexSnippet: '4500 003c 4b12 4000 4006 82a1 c0a8 0478 0a14 050f 0019 c034 ... 5354 4152 5454 4c53 0d0a 4e4f 4f50 0d0a 4155 5448 454e 5449 4341 5445',
};

const s2_starttls = analyzeStarttlsStateMachine('IMAP', 143, [
  '* OK [CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED] mail.legacy-gov.in IMAP4rev1',
  'A01 STARTTLS',
  'A01 OK Begin TLS negotiation now',
]);

const s2_tls = evaluateTlsHandshake('TLS 1.1', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'RSA-1024', {
  subject: 'CN=mail.legacy-gov.in, O=State Mail Service, C=IN',
  issuer: 'CN=Legacy Internal CA, O=State Gov',
  validFrom: '2021-01-01',
  validTo: '2023-01-01',
  daysToExpiry: -1345,
  isExpired: true,
  keyType: 'RSA',
  keyLength: 1024,
  signatureAlgorithm: 'SHA1withRSA',
  isSelfSigned: false,
  sanMatch: true,
  serialNumber: '0x8849A1F290D',
});

const s2_findings = [...s2_starttls.findings, ...s2_tls.findings];
const s2_aiScore = 0.72;
const s2_risk = calculateSessionRiskScore(s2_findings, s2_aiScore);

const session2 = {
  id: 'sess-002',
  pcapFile: 'legacy-vulnerable-mail.pcap',
  timestamp: '2026-09-08 14:12:05.118',
  srcIp: '192.168.4.145',
  srcPort: 51092,
  dstIp: '10.20.5.15',
  dstPort: 143,
  serverHostname: 'mail.legacy-gov.in',
  protocol: 'IMAP' as const,
  tlsVersion: s2_tls.version,
  cipherSuite: s2_tls.cipherSuite,
  keyExchange: s2_tls.keyExchange,
  forwardSecrecy: s2_tls.forwardSecrecy,
  starttlsState: s2_starttls.state,
  certificate: s2_tls.certificate,
  milestones: s2_starttls.milestones,
  featureVector: extractFeatureVector(s2_tls.version, s2_tls.cipherSuite, s2_tls.cipherBits, s2_tls.forwardSecrecy, s2_tls.certificate, true, false),
  findings: s2_findings,
  riskScore: s2_risk.score,
  riskTier: s2_risk.tier,
  aiAnomalyScore: s2_aiScore,
  aiExplanation: 'Gradient Boosted Tree alert: 3DES Sweet32 vulnerable cipher suite combined with expired SHA1 certificate.',
  rawHexSnippet: '4500 0038 91a4 4000 4006 3b0c c0a8 0491 0a14 050f 008f c7a2 ... 2a20 4f4b 2049 4d41 5034 7265 7631 2053 5441 5254 544c 530d 0a',
};

// Build Synthetic Dataset 2: Hardened Enterprise Mail
const s3_starttls = analyzeStarttlsStateMachine('SMTP', 587, [
  '220 mail.ntro.gov.in ESMTP Postfix (Hardened MailGateway v4.2)',
  'EHLO mta.sec.ntro.gov.in',
  '220 2.0.0 Ready to start TLS',
  'STARTTLS',
  '220 2.0.0 Go ahead with TLS',
]);

const s3_tls = evaluateTlsHandshake('TLS 1.3', 'TLS_AES_256_GCM_SHA384', 'ECDHE-P384', {
  subject: 'CN=mail.ntro.gov.in, O=National Technical Research Organisation, C=IN',
  issuer: 'CN=NTRO National Cyber Root CA v3, O=Government of India',
  validFrom: '2026-01-01',
  validTo: '2027-01-01',
  daysToExpiry: 115,
  isExpired: false,
  keyType: 'RSA',
  keyLength: 4096,
  signatureAlgorithm: 'ECDSAwithSHA384',
  isSelfSigned: false,
  sanMatch: true,
  serialNumber: '0x992B104F9A2C',
});

const s3_findings = [...s3_starttls.findings, ...s3_tls.findings];
const s3_aiScore = 0.04;
const s3_risk = calculateSessionRiskScore(s3_findings, s3_aiScore);

const session3 = {
  id: 'sess-003',
  pcapFile: 'hardened-ntro-enterprise.pcap',
  timestamp: '2026-09-08 14:30:11.890',
  srcIp: '10.100.12.50',
  srcPort: 38920,
  dstIp: '10.100.1.10',
  dstPort: 587,
  serverHostname: 'mail.ntro.gov.in',
  protocol: 'SMTP' as const,
  tlsVersion: s3_tls.version,
  cipherSuite: s3_tls.cipherSuite,
  keyExchange: s3_tls.keyExchange,
  forwardSecrecy: s3_tls.forwardSecrecy,
  starttlsState: s3_starttls.state,
  certificate: s3_tls.certificate,
  milestones: s3_starttls.milestones,
  featureVector: extractFeatureVector(s3_tls.version, s3_tls.cipherSuite, s3_tls.cipherBits, s3_tls.forwardSecrecy, s3_tls.certificate, true, false),
  findings: s3_findings,
  riskScore: s3_risk.score,
  riskTier: s3_risk.tier,
  aiAnomalyScore: s3_aiScore,
  aiExplanation: 'Normal baseline: Fully compliant with NIST SP 800-52r2 and Mozilla Modern TLS guidelines.',
  rawHexSnippet: '4500 0040 12c9 4000 4006 f48b 0a64 0c32 0a64 010a 024b 9812 ... 1603 0100 f801 0000 f403 0341 8b92 01c4 8f19 2038 9a11 2b80',
};

const s4_starttls = analyzeStarttlsStateMachine('IMAP', 993, []);
const s4_tls = evaluateTlsHandshake('TLS 1.3', 'TLS_CHACHA20_POLY1305_SHA256', 'ECDHE-P256', {
  subject: 'CN=mail.ntro.gov.in, O=National Technical Research Organisation, C=IN',
  issuer: 'CN=NTRO National Cyber Root CA v3, O=Government of India',
  validFrom: '2026-01-01',
  validTo: '2027-01-01',
  daysToExpiry: 115,
  isExpired: false,
  keyType: 'ECDSA',
  keyLength: 384,
  signatureAlgorithm: 'ECDSAwithSHA384',
  isSelfSigned: false,
  sanMatch: true,
  serialNumber: '0x992B104F9A2D',
});

const s4_findings = [...s4_starttls.findings, ...s4_tls.findings];
const s4_aiScore = 0.02;
const s4_risk = calculateSessionRiskScore(s4_findings, s4_aiScore);

const session4 = {
  id: 'sess-004',
  pcapFile: 'hardened-ntro-enterprise.pcap',
  timestamp: '2026-09-08 14:32:44.201',
  srcIp: '10.100.14.88',
  srcPort: 44102,
  dstIp: '10.100.1.10',
  dstPort: 993,
  serverHostname: 'mail.ntro.gov.in',
  protocol: 'IMAP' as const,
  tlsVersion: s4_tls.version,
  cipherSuite: s4_tls.cipherSuite,
  keyExchange: s4_tls.keyExchange,
  forwardSecrecy: s4_tls.forwardSecrecy,
  starttlsState: s4_starttls.state,
  certificate: s4_tls.certificate,
  milestones: s4_starttls.milestones,
  featureVector: extractFeatureVector(s4_tls.version, s4_tls.cipherSuite, s4_tls.cipherBits, s4_tls.forwardSecrecy, s4_tls.certificate, true, false),
  findings: s4_findings,
  riskScore: s4_risk.score,
  riskTier: s4_risk.tier,
  aiAnomalyScore: s4_aiScore,
  aiExplanation: 'Implicit TLS session: Clean handshake with ChaCha20-Poly1305 and ECDSA curve P-384.',
  rawHexSnippet: '4500 003c 88a1 4000 4006 b112 0a64 0e58 0a64 010a 03e1 ad80 ... 1603 0301 2001 0001 1c03 0399 f412 a0b1 a482 e105 a8b2 1904',
};

// Build Synthetic Dataset 3: Downgrade & Stripping Attack
const s5_starttls = analyzeStarttlsStateMachine('SMTP', 25, [
  '220 mail.agency-ops.gov.in ESMTP Postfix',
  'EHLO attacker-tap.net',
  '220-STARTTLS',
  'AUTH PLAIN AGFsaWNlAFBhc3N3b3JkMTIz', // Credential transmitted cleartext!
]);

const s5_tls = evaluateTlsHandshake('None (Plaintext)', 'None', 'None', undefined);
const s5_findings = [...s5_starttls.findings, ...s5_tls.findings];
const s5_aiScore = 0.95;
const s5_risk = calculateSessionRiskScore(s5_findings, s5_aiScore);

const session5 = {
  id: 'sess-005',
  pcapFile: 'downgrade-stripping-attack.pcap',
  timestamp: '2026-09-08 14:50:00.112',
  srcIp: '198.51.100.44',
  srcPort: 60128,
  dstIp: '203.0.113.88',
  dstPort: 25,
  serverHostname: 'mail.agency-ops.gov.in',
  protocol: 'SMTP' as const,
  tlsVersion: s5_tls.version,
  cipherSuite: s5_tls.cipherSuite,
  keyExchange: s5_tls.keyExchange,
  forwardSecrecy: false,
  starttlsState: s5_starttls.state,
  certificate: undefined,
  milestones: s5_starttls.milestones,
  featureVector: extractFeatureVector('None (Plaintext)', 'None', 0, false, undefined, false, true),
  findings: s5_findings,
  riskScore: s5_risk.score,
  riskTier: s5_risk.tier,
  aiAnomalyScore: s5_aiScore,
  aiExplanation: 'CRITICAL ANOMALY: Active STARTTLS stripping attack detected. Plaintext AUTH credentials intercepted on wire.',
  rawHexSnippet: '4500 0048 3120 4000 4006 1a88 c633 642c c700 7158 0019 ad99 ... 4155 5448 2050 4c41 494e 2041 4746 7361 574e 6c41 4642 6863',
};

// Assemble Forensic PCAP Datasets
export const SAMPLE_PCAP_DATASETS: ForensicPcapDataset[] = [
  {
    id: 'ds-legacy',
    name: 'Vulnerable Legacy Mail Infrastructure (legacy-vulnerable-mail.pcap)',
    description: 'PCAP capture of an un-hardened mail server running TLS 1.0, RC4, 1024-bit expired RSA certs, and detected STARTTLS command injection.',
    uploadedAt: '2026-09-08 14:15:00',
    totalPackets: 1842,
    fileSizeBytes: 2459120,
    sessions: [session1, session2],
    summary: computeSecurityPostureSummary([session1, session2]),
  },
  {
    id: 'ds-hardened',
    name: 'Hardened NTRO Enterprise Infrastructure (hardened-ntro-enterprise.pcap)',
    description: 'PCAP capture of hardened government email infrastructure running TLS 1.3, ECDHE-P384 key exchange, and strict MTA-STS policies.',
    uploadedAt: '2026-09-08 14:35:00',
    totalPackets: 3290,
    fileSizeBytes: 4182900,
    sessions: [session3, session4],
    summary: computeSecurityPostureSummary([session3, session4]),
  },
  {
    id: 'ds-stripping',
    name: 'Active STARTTLS Stripping Attack (downgrade-stripping-attack.pcap)',
    description: 'PCAP capture from a tap detecting an active MITM downgrade attack and cleartext credential transmission.',
    uploadedAt: '2026-09-08 14:52:00',
    totalPackets: 910,
    fileSizeBytes: 1120400,
    sessions: [session5, session1],
    summary: computeSecurityPostureSummary([session5, session1]),
  },
];
