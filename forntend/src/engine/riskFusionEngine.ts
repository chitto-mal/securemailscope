import type { MailSession, SecurityFinding, SecurityPostureSummary, PostureSubScore, RiskSeverity } from '../types/pcap';

export function calculateSessionRiskScore(
  findings: SecurityFinding[],
  aiAnomalyScore: number
): { score: number; tier: RiskSeverity } {
  let penalty = 0;

  for (const f of findings) {
    switch (f.severity) {
      case 'CRITICAL':
        penalty += 35;
        break;
      case 'HIGH':
        penalty += 20;
        break;
      case 'MEDIUM':
        penalty += 10;
        break;
      case 'LOW':
        penalty += 4;
        break;
    }
  }

  // Add AI anomaly penalty if anomaly vector detected
  if (aiAnomalyScore > 0.7) {
    penalty += Math.round(aiAnomalyScore * 15);
  }

  const score = Math.max(0, Math.min(100, 100 - penalty));

  let tier: RiskSeverity = 'SECURE';
  if (score < 40) tier = 'CRITICAL';
  else if (score < 60) tier = 'HIGH';
  else if (score < 80) tier = 'MEDIUM';
  else if (score < 95) tier = 'LOW';

  return { score, tier };
}

export function computeSecurityPostureSummary(sessions: MailSession[]): SecurityPostureSummary {
  if (sessions.length === 0) {
    return {
      overallScore: 0,
      postureTier: 'CRITICAL',
      totalSessions: 0,
      criticalSessions: 0,
      highSessions: 0,
      mediumSessions: 0,
      lowSessions: 0,
      secureSessions: 0,
      subScores: createDefaultSubScores(0, 0, 0, 0, 0, 0, 0),
      topIssues: [],
      remediationPriority: [],
    };
  }

  let totalScoreSum = 0;
  let criticalSessions = 0;
  let highSessions = 0;
  let mediumSessions = 0;
  let lowSessions = 0;
  let secureSessions = 0;

  let tlsScoreSum = 0;
  let cipherScoreSum = 0;
  let certScoreSum = 0;
  let keyExScoreSum = 0;
  let pfsScoreSum = 0;
  let starttlsScoreSum = 0;
  let aiScoreSum = 0;

  const allFindings: SecurityFinding[] = [];

  sessions.forEach((s) => {
    totalScoreSum += s.riskScore;

    switch (s.riskTier) {
      case 'CRITICAL': criticalSessions++; break;
      case 'HIGH': highSessions++; break;
      case 'MEDIUM': mediumSessions++; break;
      case 'LOW': lowSessions++; break;
      case 'SECURE': secureSessions++; break;
    }

    allFindings.push(...s.findings);

    // Calculate sub-scores per session
    // TLS Security (/20)
    if (s.tlsVersion === 'TLS 1.3') tlsScoreSum += 20;
    else if (s.tlsVersion === 'TLS 1.2') tlsScoreSum += 16;
    else if (s.tlsVersion === 'TLS 1.1') tlsScoreSum += 8;
    else if (s.tlsVersion === 'TLS 1.0') tlsScoreSum += 4;
    else tlsScoreSum += 0;

    // Cipher Strength (/20)
    if (s.cipherSuite.includes('AES') || s.cipherSuite.includes('CHACHA')) {
      cipherScoreSum += s.cipherSuite.includes('GCM') ? 20 : 15;
    } else if (s.cipherSuite.includes('3DES')) cipherScoreSum += 8;
    else if (s.cipherSuite.includes('RC4')) cipherScoreSum += 2;
    else cipherScoreSum += 10;

    // Certificate Security (/20)
    if (s.certificate) {
      let cScore = 20;
      if (s.certificate.isExpired) cScore -= 12;
      if (s.certificate.keyLength < 2048) cScore -= 6;
      if (s.certificate.isSelfSigned) cScore -= 4;
      if (s.certificate.signatureAlgorithm.includes('SHA1') || s.certificate.signatureAlgorithm.includes('MD5')) cScore -= 5;
      certScoreSum += Math.max(0, cScore);
    } else {
      certScoreSum += 10;
    }

    // Key Exchange (/15)
    if (s.keyExchange.includes('ECDHE') || s.keyExchange.includes('P-384') || s.keyExchange.includes('P-256')) keyExScoreSum += 15;
    else if (s.keyExchange.includes('DHE')) keyExScoreSum += 12;
    else if (s.keyExchange.includes('RSA')) keyExScoreSum += 6;
    else keyExScoreSum += 8;

    // Forward Secrecy (/10)
    pfsScoreSum += s.forwardSecrecy ? 10 : 2;

    // STARTTLS Security (/10)
    if (s.starttlsState === 'IMPLICIT_TLS' || s.starttlsState === 'SUCCESSFUL') starttlsScoreSum += 10;
    else if (s.starttlsState === 'INJECTION_DETECTED') starttlsScoreSum += 1;
    else if (s.starttlsState === 'STRIPPED_ATTACK') starttlsScoreSum += 2;
    else starttlsScoreSum += 5;

    // AI Behavior Score (/5)
    aiScoreSum += s.aiAnomalyScore < 0.3 ? 5 : s.aiAnomalyScore < 0.7 ? 3 : 1;
  });

  const n = sessions.length;
  const avgOverallScore = Math.round(totalScoreSum / n);

  let overallTier: RiskSeverity = 'SECURE';
  if (avgOverallScore < 40) overallTier = 'CRITICAL';
  else if (avgOverallScore < 60) overallTier = 'HIGH';
  else if (avgOverallScore < 80) overallTier = 'MEDIUM';
  else if (avgOverallScore < 95) overallTier = 'LOW';

  // Deduplicate top issues by ID
  const uniqueFindingsMap = new Map<string, SecurityFinding>();
  allFindings.forEach((f) => uniqueFindingsMap.set(f.id, f));
  const topIssues = Array.from(uniqueFindingsMap.values()).sort((a, b) => {
    const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, SECURE: 0 };
    return rank[b.severity] - rank[a.severity];
  });

  // Actionable remediation priority list
  const remediationPriority: string[] = [];
  if (topIssues.some((i) => i.id === 'f-starttls-inject')) remediationPriority.push('Fix STARTTLS command injection buffer validation on mail server');
  if (topIssues.some((i) => i.id === 'f-cert-expired')) remediationPriority.push('Replace expired X.509 server certificate');
  if (topIssues.some((i) => i.id === 'f-cipher-rc4')) remediationPriority.push('Remove RC4 cipher suites immediately (RFC 7465)');
  if (topIssues.some((i) => i.id.startsWith('f-tls-ver'))) remediationPriority.push('Disable legacy TLS 1.0/1.1 protocols (RFC 8996)');
  if (topIssues.some((i) => i.id === 'f-cert-weak-rsa')) remediationPriority.push('Upgrade RSA key length to ≥ 2048 bits or ECDSA P-256');
  if (topIssues.some((i) => i.id === 'f-no-pfs')) remediationPriority.push('Enable Perfect Forward Secrecy with ECDHE suites');
  if (topIssues.some((i) => i.id === 'f-starttls-strip')) remediationPriority.push('Enforce MTA-STS (RFC 8461) to prevent STARTTLS stripping');

  if (remediationPriority.length === 0) {
    remediationPriority.push('Maintain current hardening configuration and schedule periodic PCAP cryptographic audits.');
  }

  return {
    overallScore: avgOverallScore,
    postureTier: overallTier,
    totalSessions: n,
    criticalSessions,
    highSessions,
    mediumSessions,
    lowSessions,
    secureSessions,
    subScores: createDefaultSubScores(
      Math.round(tlsScoreSum / n),
      Math.round(cipherScoreSum / n),
      Math.round(certScoreSum / n),
      Math.round(keyExScoreSum / n),
      Math.round(pfsScoreSum / n),
      Math.round(starttlsScoreSum / n),
      Math.round(aiScoreSum / n)
    ),
    topIssues: topIssues.slice(0, 5),
    remediationPriority,
  };
}

function createDefaultSubScores(
  tls: number,
  cipher: number,
  cert: number,
  keyEx: number,
  pfs: number,
  starttls: number,
  ai: number
) {
  const statusOf = (score: number, max: number): PostureSubScore['status'] => {
    const ratio = score / max;
    if (ratio >= 0.85) return 'EXCELLENT';
    if (ratio >= 0.70) return 'GOOD';
    if (ratio >= 0.50) return 'WARNING';
    return 'CRITICAL';
  };

  return {
    tlsSecurity: { name: 'TLS Protocol Security', score: tls, maxScore: 20, weight: 20, status: statusOf(tls, 20) },
    cipherStrength: { name: 'Cipher Suite Strength', score: cipher, maxScore: 20, weight: 20, status: statusOf(cipher, 20) },
    certificateSecurity: { name: 'Certificate Security', score: cert, maxScore: 20, weight: 20, status: statusOf(cert, 20) },
    keyExchange: { name: 'Key Exchange Integrity', score: keyEx, maxScore: 15, weight: 15, status: statusOf(keyEx, 15) },
    forwardSecrecy: { name: 'Forward Secrecy (PFS)', score: pfs, maxScore: 10, weight: 10, status: statusOf(pfs, 10) },
    starttlsSecurity: { name: 'STARTTLS Protocol Handler', score: starttls, maxScore: 10, weight: 10, status: statusOf(starttls, 10) },
    aiBehaviorScore: { name: 'AI Anomaly Baseline Score', score: ai, maxScore: 5, weight: 5, status: statusOf(ai, 5) },
  };
}
