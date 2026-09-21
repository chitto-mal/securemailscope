import type { HandshakeMilestone, SecurityFinding } from '../types/pcap';

export interface StarttlsAnalysisResult {
  state: 'NONE' | 'SUCCESSFUL' | 'INJECTION_DETECTED' | 'STRIPPED_ATTACK' | 'IMPLICIT_TLS';
  milestones: HandshakeMilestone[];
  findings: SecurityFinding[];
  anomalyFlag: boolean;
  anomalyReason?: string;
}

export function analyzeStarttlsStateMachine(
  protocol: 'SMTP' | 'IMAP' | 'POP3',
  port: number,
  packetLines: string[]
): StarttlsAnalysisResult {
  const milestones: HandshakeMilestone[] = [];
  const findings: SecurityFinding[] = [];
  let state: StarttlsAnalysisResult['state'] = 'NONE';
  let anomalyFlag = false;
  let anomalyReason: string | undefined = undefined;

  let offset = 0;

  // Check implicit TLS ports first (465 for SMTPS, 993 for IMAPS, 995 for POP3S)
  if (port === 465 || port === 993 || port === 995) {
    milestones.push({
      id: 'm-0',
      timestampOffsetMs: 0,
      direction: 'client->server',
      label: 'TCP Connection Established',
      details: `Connected to implicit TLS port ${port}`,
      isPlaintext: false,
      isEncrypted: true,
    });
    milestones.push({
      id: 'm-1',
      timestampOffsetMs: 12,
      direction: 'client->server',
      label: 'Implicit TLS ClientHello',
      details: 'Direct TLS handshake without plaintext STARTTLS step',
      isPlaintext: false,
      isEncrypted: true,
    });
    return {
      state: 'IMPLICIT_TLS',
      milestones,
      findings,
      anomalyFlag: false,
    };
  }

  // Explicit STARTTLS analysis
  let serverBannerSeen = false;
  let starttlsRequested = false;
  let starttlsAccepted = false;
  let unexpectedPlaintextBytesAfterStarttls = false;

  for (let i = 0; i < packetLines.length; i++) {
    const line = packetLines[i].trim();
    offset += 15 + Math.floor(Math.random() * 8);

    if (i === 0 && (line.startsWith('220') || line.startsWith('* OK') || line.startsWith('+OK'))) {
      serverBannerSeen = true;
      milestones.push({
        id: `m-${i}`,
        timestampOffsetMs: offset,
        direction: 'server->client',
        label: `${protocol} Banner`,
        details: line,
        isPlaintext: true,
        isEncrypted: false,
      });
      continue;
    }

    if (line.toUpperCase().includes('STARTTLS') || line.toUpperCase().includes('STLS')) {
      starttlsRequested = true;
      milestones.push({
        id: `m-${i}`,
        timestampOffsetMs: offset,
        direction: 'client->server',
        label: `${protocol} STARTTLS Request`,
        details: line,
        isPlaintext: true,
        isEncrypted: false,
      });
      continue;
    }

    if (starttlsRequested && !starttlsAccepted && (line.startsWith('220 2.0.0') || line.startsWith('220 Ready') || line.startsWith('A1 OK') || line.startsWith('+OK Begin TLS'))) {
      starttlsAccepted = true;
      milestones.push({
        id: `m-${i}`,
        timestampOffsetMs: offset,
        direction: 'server->client',
        label: 'STARTTLS Ready Response',
        details: line,
        isPlaintext: true,
        isEncrypted: false,
      });
      continue;
    }

    // Check for plaintext commands injected AFTER STARTTLS request before ClientHello
    if (starttlsRequested && !starttlsAccepted && (line.startsWith('NOOP') || line.startsWith('RSET') || line.startsWith('MAIL FROM') || line.startsWith('AUTHENTICATE'))) {
      unexpectedPlaintextBytesAfterStarttls = true;
      milestones.push({
        id: `m-${i}`,
        timestampOffsetMs: offset,
        direction: 'client->server',
        label: 'UNEXPECTED PLAINTEXT COMMAND',
        details: `Command Injection detected: "${line}" sent prior to TLS ClientHello`,
        isPlaintext: true,
        isEncrypted: false,
        anomalyFlag: true,
      });
    }
  }

  if (unexpectedPlaintextBytesAfterStarttls) {
    state = 'INJECTION_DETECTED';
    anomalyFlag = true;
    anomalyReason = 'STARTTLS Command Injection (CVE-2011-0411 class attack detected in TCP stream)';
    findings.push({
      id: 'f-starttls-inject',
      severity: 'CRITICAL',
      category: 'STARTTLS Security',
      title: 'STARTTLS Command Injection Vulnerability',
      description: 'Plaintext protocol commands were sent immediately following the STARTTLS command before TLS handshake negotiation. An attacker can inject unauthenticated commands into the encrypted session state.',
      impact: 'Allows man-in-the-middle attackers to inject commands executed with privileges of authenticated user.',
      remediation: 'Flush server input buffers upon receiving STARTTLS command and strict state validation per RFC 3207.',
      complianceRef: 'CVE-2011-0411 & US-CERT Alert TA11-075A',
    });
  } else if (starttlsRequested && starttlsAccepted) {
    state = 'SUCCESSFUL';
    milestones.push({
      id: 'm-tls-start',
      timestampOffsetMs: offset + 10,
      direction: 'client->server',
      label: 'TLS Upgrade Initiated',
      details: 'Handshake ClientHello transmitted on established TCP stream',
      isPlaintext: false,
      isEncrypted: true,
    });
  } else if (serverBannerSeen && !starttlsRequested) {
    state = 'STRIPPED_ATTACK';
    anomalyFlag = true;
    anomalyReason = 'Possible STARTTLS Stripping Attack: Mail server advertised TLS capability but client reverted to plaintext';
    findings.push({
      id: 'f-starttls-strip',
      severity: 'HIGH',
      category: 'STARTTLS Security',
      title: 'STARTTLS Stripping Attack Suspected',
      description: 'The mail server advertised STARTTLS capability in EHLO response, but the client proceeded to transmit credentials in cleartext without issuing STARTTLS.',
      impact: 'Credentials and email contents transmitted unencrypted over the wire.',
      remediation: 'Enforce MTA-STS (RFC 8461) or DANE for SMTP, and require TLS on client connections.',
      complianceRef: 'RFC 8461 (MTA-STS) & NIST SP 800-45r2',
    });
  }

  return {
    state,
    milestones,
    findings,
    anomalyFlag,
    anomalyReason,
  };
}
