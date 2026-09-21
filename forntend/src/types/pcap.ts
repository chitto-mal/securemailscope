export type ProtocolType = 'SMTP' | 'IMAP' | 'POP3';

export type TLSVersion = 'TLS 1.0' | 'TLS 1.1' | 'TLS 1.2' | 'TLS 1.3' | 'None (Plaintext)';

export type RiskSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SECURE';

export interface X509Certificate {
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  daysToExpiry: number;
  isExpired: boolean;
  keyType: 'RSA' | 'ECDSA' | 'DSA';
  keyLength: number; // e.g. 1024, 2048, 4096, 256, 384
  signatureAlgorithm: 'MD5withRSA' | 'SHA1withRSA' | 'SHA256withRSA' | 'ECDSAwithSHA384';
  isSelfSigned: boolean;
  sanMatch: boolean;
  serialNumber: string;
}

export interface HandshakeMilestone {
  id: string;
  timestampOffsetMs: number;
  direction: 'client->server' | 'server->client';
  label: string;
  details: string;
  isPlaintext: boolean;
  isEncrypted: boolean;
  anomalyFlag?: boolean;
}

export interface SecurityFinding {
  id: string;
  severity: RiskSeverity;
  category: 'TLS Protocol' | 'Cipher Suite' | 'Certificate' | 'Key Exchange' | 'STARTTLS Security' | 'AI Anomaly' | 'Forward Secrecy';
  title: string;
  description: string;
  impact: string;
  remediation: string;
  complianceRef: string; // e.g. "NIST SP 800-52r2 Section 3.1" or "IETF RFC 8996"
}

export interface SessionFeatureVector {
  tlsVersion: TLSVersion;
  cipherSuite: string;
  cipherBits: number;
  forwardSecrecy: boolean;
  certKeyLength: number;
  certIsExpired: boolean;
  certIsSelfSigned: boolean;
  certSigAlgoWeak: boolean;
  starttlsUsed: boolean;
  starttlsAnomalyFlag: boolean;
  handshakeRttMs: number;
  sessionResumption: boolean;
}

export interface MailSession {
  id: string;
  pcapFile: string;
  timestamp: string;
  srcIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  serverHostname: string;
  protocol: ProtocolType;
  tlsVersion: TLSVersion;
  cipherSuite: string;
  keyExchange: string;
  forwardSecrecy: boolean;
  starttlsState: 'NONE' | 'SUCCESSFUL' | 'INJECTION_DETECTED' | 'STRIPPED_ATTACK' | 'IMPLICIT_TLS';
  certificate?: X509Certificate;
  milestones: HandshakeMilestone[];
  featureVector: SessionFeatureVector;
  findings: SecurityFinding[];
  riskScore: number; // 0-100 (0 = worst, 100 = best)
  riskTier: RiskSeverity;
  aiAnomalyScore: number; // 0.0 - 1.0 (0 = normal baseline, 0.8+ = anomaly)
  aiExplanation: string;
  rawHexSnippet: string;
}

export interface PostureSubScore {
  name: string;
  score: number;
  maxScore: number;
  weight: number;
  status: 'EXCELLENT' | 'GOOD' | 'WARNING' | 'CRITICAL';
}

export interface SecurityPostureSummary {
  overallScore: number; // 0-100
  postureTier: RiskSeverity;
  totalSessions: number;
  criticalSessions: number;
  highSessions: number;
  mediumSessions: number;
  lowSessions: number;
  secureSessions: number;
  subScores: {
    tlsSecurity: PostureSubScore;
    cipherStrength: PostureSubScore;
    certificateSecurity: PostureSubScore;
    keyExchange: PostureSubScore;
    forwardSecrecy: PostureSubScore;
    starttlsSecurity: PostureSubScore;
    aiBehaviorScore: PostureSubScore;
  };
  topIssues: SecurityFinding[];
  remediationPriority: string[];
}

export interface ForensicPcapDataset {
  id: string;
  name: string;
  description: string;
  uploadedAt: string;
  totalPackets: number;
  fileSizeBytes: number;
  sessions: MailSession[];
  summary: SecurityPostureSummary;
}
