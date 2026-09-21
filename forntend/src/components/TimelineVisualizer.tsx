import React from 'react';
import type { MailSession } from '../types/pcap';
import { Clock, ArrowRight, Lock, Unlock } from 'lucide-react';

interface TimelineVisualizerProps {
  session: MailSession;
}

export const TimelineVisualizer: React.FC<TimelineVisualizerProps> = ({ session }) => {
  const { milestones, starttlsState, protocol } = session;

  return (
    <div className="glass-panel" style={{ padding: '20px', marginBottom: '24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
        <div>
          <h3 style={{ fontSize: '15px', fontWeight: '700', color: '#ffffff', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Clock size={18} color="var(--accent-cyan)" />
            <span>Cryptographic Handshake Timeline & STARTTLS Boundary</span>
          </h3>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px' }}>
            Reconstructed TCP stream timeline for {protocol} session <code className="font-mono" style={{ color: 'var(--accent-cyan)' }}>{session.id}</code> ({session.srcIp}:{session.srcPort} → {session.dstIp}:{session.dstPort})
          </p>
        </div>

        {/* State Tag */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          {starttlsState === 'INJECTION_DETECTED' && (
            <span className="badge-critical font-mono" style={{ padding: '4px 10px', borderRadius: '6px', fontSize: '11px', fontWeight: '700' }}>
              CRITICAL: COMMAND INJECTION
            </span>
          )}
          {starttlsState === 'STRIPPED_ATTACK' && (
            <span className="badge-high font-mono" style={{ padding: '4px 10px', borderRadius: '6px', fontSize: '11px', fontWeight: '700' }}>
              HIGH: STARTTLS STRIPPED
            </span>
          )}
          {starttlsState === 'SUCCESSFUL' && (
            <span className="badge-secure font-mono" style={{ padding: '4px 10px', borderRadius: '6px', fontSize: '11px', fontWeight: '700' }}>
              STARTTLS UPGRADE SUCCESS
            </span>
          )}
          {starttlsState === 'IMPLICIT_TLS' && (
            <span className="badge-secure font-mono" style={{ padding: '4px 10px', borderRadius: '6px', fontSize: '11px', fontWeight: '700' }}>
              IMPLICIT TLS DIRECT
            </span>
          )}
        </div>
      </div>

      {/* Horizontal Milestone Tracker */}
      <div style={{ display: 'flex', overflowX: 'auto', paddingBottom: '12px', gap: '12px' }}>
        {milestones.map((m, idx) => (
          <React.Fragment key={m.id}>
            
            {/* Step Card */}
            <div style={{
              minWidth: '220px',
              background: m.anomalyFlag
                ? 'rgba(239, 68, 68, 0.12)'
                : m.isEncrypted
                ? 'rgba(16, 185, 129, 0.08)'
                : 'rgba(255, 255, 255, 0.03)',
              border: `1px solid ${
                m.anomalyFlag
                  ? 'rgba(239, 68, 68, 0.5)'
                  : m.isEncrypted
                  ? 'rgba(16, 185, 129, 0.3)'
                  : 'var(--border-subtle)'
              }`,
              borderRadius: '10px',
              padding: '12px',
              position: 'relative'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                <span className="font-mono" style={{ fontSize: '11px', color: 'var(--accent-cyan)', fontWeight: '600' }}>
                  +{m.timestampOffsetMs}ms
                </span>
                <span style={{
                  fontSize: '10px',
                  padding: '2px 6px',
                  borderRadius: '4px',
                  background: m.direction === 'client->server' ? 'rgba(59, 130, 246, 0.2)' : 'rgba(139, 92, 246, 0.2)',
                  color: m.direction === 'client->server' ? '#93c5fd' : '#c4b5fd',
                  fontWeight: '600'
                }}>
                  {m.direction === 'client->server' ? 'C → S' : 'S → C'}
                </span>
              </div>

              <div style={{ fontWeight: '700', fontSize: '13px', color: m.anomalyFlag ? '#fca5a5' : '#ffffff', marginBottom: '4px' }}>
                {m.label}
              </div>

              <div className="font-mono" style={{ fontSize: '11px', color: m.anomalyFlag ? '#fecaca' : 'var(--text-muted)', wordBreak: 'break-all' }}>
                {m.details}
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '4px', marginTop: '8px' }}>
                {m.isEncrypted ? (
                  <span style={{ fontSize: '10px', color: 'var(--accent-emerald)', display: 'flex', alignItems: 'center', gap: '3px' }}>
                    <Lock size={12} /> Encrypted Layer
                  </span>
                ) : (
                  <span style={{ fontSize: '10px', color: 'var(--text-dim)', display: 'flex', alignItems: 'center', gap: '3px' }}>
                    <Unlock size={12} /> Cleartext TCP
                  </span>
                )}
              </div>
            </div>

            {/* Connecting Arrow */}
            {idx < milestones.length - 1 && (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '0 4px' }}>
                <ArrowRight size={16} color="var(--text-dim)" />
              </div>
            )}

          </React.Fragment>
        ))}
      </div>
    </div>
  );
};
