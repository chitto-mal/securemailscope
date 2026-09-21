import React, { useState } from 'react';
import type { MailSession, RiskSeverity } from '../types/pcap';
import { Search, Eye, Filter, AlertTriangle } from 'lucide-react';

interface SessionsTableProps {
  sessions: MailSession[];
  onInspectSession: (session: MailSession) => void;
  selectedSessionId?: string;
}

export const SessionsTable: React.FC<SessionsTableProps> = ({
  sessions,
  onInspectSession,
  selectedSessionId,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');

  const filteredSessions = sessions.filter((s) => {
    const matchesSearch =
      s.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      s.serverHostname.toLowerCase().includes(searchTerm.toLowerCase()) ||
      s.srcIp.includes(searchTerm) ||
      s.dstIp.includes(searchTerm) ||
      s.cipherSuite.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesSeverity = severityFilter === 'ALL' || s.riskTier === severityFilter;

    return matchesSearch && matchesSeverity;
  });

  const getTierBadgeClass = (tier: RiskSeverity) => {
    switch (tier) {
      case 'CRITICAL': return 'badge-critical';
      case 'HIGH': return 'badge-high';
      case 'MEDIUM': return 'badge-medium';
      case 'LOW': return 'badge-low';
      case 'SECURE': return 'badge-secure';
    }
  };

  return (
    <div className="glass-panel" style={{ padding: '20px', marginBottom: '24px' }}>
      
      {/* Table Controls */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', marginBottom: '16px' }}>
        <div>
          <h3 style={{ fontSize: '15px', fontWeight: '700', color: '#ffffff' }}>
            Analyzed Mail Traffic Sessions ({filteredSessions.length})
          </h3>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Passive TCP stream reconstructions with extracted ClientHello / ServerHello & X.509 cert metadata
          </p>
        </div>

        {/* Search & Severity Filter */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{ position: 'relative' }}>
            <Search size={14} color="var(--text-muted)" style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)' }} />
            <input
              type="text"
              placeholder="Search IP, host, cipher..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{
                background: 'rgba(255, 255, 255, 0.05)',
                color: '#ffffff',
                border: '1px solid var(--border-subtle)',
                borderRadius: '8px',
                padding: '6px 12px 6px 30px',
                fontSize: '12px',
                outline: 'none',
                width: '200px'
              }}
            />
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Filter size={14} color="var(--text-muted)" />
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              style={{
                background: '#1f2937',
                color: '#ffffff',
                border: '1px solid var(--border-subtle)',
                borderRadius: '8px',
                padding: '6px 10px',
                fontSize: '12px',
                outline: 'none',
                cursor: 'pointer'
              }}
            >
              <option value="ALL">All Risk Tiers</option>
              <option value="CRITICAL">Critical Only</option>
              <option value="HIGH">High Risk</option>
              <option value="MEDIUM">Medium Risk</option>
              <option value="SECURE">Secure</option>
            </select>
          </div>
        </div>
      </div>

      {/* Table View */}
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              <th style={{ padding: '10px 12px' }}>Session ID</th>
              <th style={{ padding: '10px 12px' }}>Protocol</th>
              <th style={{ padding: '10px 12px' }}>Client → Server</th>
              <th style={{ padding: '10px 12px' }}>TLS Version</th>
              <th style={{ padding: '10px 12px' }}>Negotiated Cipher</th>
              <th style={{ padding: '10px 12px' }}>Cert Info</th>
              <th style={{ padding: '10px 12px' }}>Posture Score</th>
              <th style={{ padding: '10px 12px', textAlign: 'right' }}>Action</th>
            </tr>
          </thead>
          <tbody>
            {filteredSessions.length === 0 ? (
              <tr>
                <td colSpan={8} style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)' }}>
                  No sessions match the current search filter.
                </td>
              </tr>
            ) : (
              filteredSessions.map((s) => (
                <tr
                  key={s.id}
                  style={{
                    borderBottom: '1px solid rgba(255,255,255,0.04)',
                    background: selectedSessionId === s.id ? 'rgba(6, 182, 212, 0.08)' : 'transparent',
                    transition: 'background 0.15s ease'
                  }}
                >
                  <td style={{ padding: '12px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <code className="font-mono" style={{ color: 'var(--accent-cyan)', fontWeight: '600' }}>
                        {s.id}
                      </code>
                      {s.featureVector.starttlsAnomalyFlag && (
                        <span title="STARTTLS Anomaly Flagged">
                          <AlertTriangle size={14} color="var(--accent-rose)" />
                        </span>
                      )}
                    </div>
                  </td>

                  <td style={{ padding: '12px' }}>
                    <span style={{
                      background: 'rgba(255, 255, 255, 0.06)',
                      padding: '3px 8px',
                      borderRadius: '4px',
                      fontSize: '11px',
                      fontWeight: '700',
                      color: '#ffffff'
                    }}>
                      {s.protocol}:{s.dstPort}
                    </span>
                  </td>

                  <td style={{ padding: '12px' }}>
                    <div style={{ fontSize: '12px', color: '#ffffff', fontWeight: '500' }}>
                      {s.serverHostname}
                    </div>
                    <div className="font-mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                      {s.srcIp}:{s.srcPort} → {s.dstIp}:{s.dstPort}
                    </div>
                  </td>

                  <td style={{ padding: '12px' }}>
                    <span style={{
                      color: s.tlsVersion === 'TLS 1.3' ? 'var(--accent-emerald)' : s.tlsVersion === 'TLS 1.0' ? 'var(--accent-rose)' : '#ffffff',
                      fontWeight: '600'
                    }}>
                      {s.tlsVersion}
                    </span>
                  </td>

                  <td style={{ padding: '12px' }}>
                    <div className="font-mono" style={{ fontSize: '11px', color: s.cipherSuite.includes('RC4') ? 'var(--accent-rose)' : 'var(--text-main)' }}>
                      {s.cipherSuite}
                    </div>
                    <div style={{ fontSize: '10px', color: 'var(--text-dim)' }}>
                      Key Exchange: {s.keyExchange} {s.forwardSecrecy && '(PFS)'}
                    </div>
                  </td>

                  <td style={{ padding: '12px' }}>
                    {s.certificate ? (
                      <div>
                        <span style={{ fontSize: '11px', color: s.certificate.isExpired ? 'var(--accent-rose)' : 'var(--text-muted)' }}>
                          RSA-{s.certificate.keyLength} {s.certificate.isExpired && '[EXPIRED]'}
                        </span>
                      </div>
                    ) : (
                      <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>None</span>
                    )}
                  </td>

                  <td style={{ padding: '12px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className={getTierBadgeClass(s.riskTier)} style={{ padding: '3px 8px', borderRadius: '10px', fontSize: '11px', fontWeight: '700' }}>
                        {s.riskScore}/100
                      </span>
                    </div>
                  </td>

                  <td style={{ padding: '12px', textAlign: 'right' }}>
                    <button
                      onClick={() => onInspectSession(s)}
                      style={{
                        background: 'rgba(6, 182, 212, 0.12)',
                        color: 'var(--accent-cyan)',
                        border: '1px solid rgba(6, 182, 212, 0.3)',
                        borderRadius: '6px',
                        padding: '5px 10px',
                        fontSize: '12px',
                        fontWeight: '600',
                        cursor: 'pointer',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '4px',
                        transition: 'all 0.15s ease'
                      }}
                    >
                      <Eye size={13} />
                      <span>Inspect</span>
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
