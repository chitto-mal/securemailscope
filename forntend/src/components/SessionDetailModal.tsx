import React from 'react';
import type { MailSession } from '../types/pcap';
import { X, ShieldAlert, Lock, Terminal } from 'lucide-react';
import { TimelineVisualizer } from './TimelineVisualizer';

interface SessionDetailModalProps {
  session: MailSession | null;
  onClose: () => void;
}

export const SessionDetailModal: React.FC<SessionDetailModalProps> = ({ session, onClose }) => {
  if (!session) return null;

  const {
    id,
    pcapFile,
    timestamp,
    tlsVersion,
    cipherSuite,
    keyExchange,
    certificate,
    findings,
    riskScore,
    riskTier,
    aiAnomalyScore,
    aiExplanation,
    rawHexSnippet,
  } = session;

  return (
    <div style={{
      position: 'fixed',
      top: 0, left: 0, right: 0, bottom: 0,
      background: 'rgba(5, 8, 15, 0.85)',
      backdropFilter: 'blur(10px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1000,
      padding: '20px'
    }}>
      <div className="glass-panel" style={{
        width: '100%',
        maxWidth: '900px',
        maxHeight: '90vh',
        overflowY: 'auto',
        padding: '28px',
        position: 'relative',
        boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.7)'
      }}>
        
        {/* Close Button */}
        <button
          onClick={onClose}
          style={{
            position: 'absolute',
            top: '20px',
            right: '20px',
            background: 'rgba(255, 255, 255, 0.08)',
            border: 'none',
            color: 'var(--text-muted)',
            borderRadius: '50%',
            width: '32px',
            height: '32px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            cursor: 'pointer'
          }}
        >
          <X size={18} />
        </button>

        {/* Modal Header */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '20px' }}>
          <div style={{
            background: 'rgba(6, 182, 212, 0.15)',
            padding: '12px',
            borderRadius: '12px',
            border: '1px solid rgba(6, 182, 212, 0.3)'
          }}>
            <Lock size={24} color="var(--accent-cyan)" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <h2 style={{ fontSize: '20px', fontWeight: '800', color: '#ffffff' }}>
                Forensic Session Inspector: <code className="font-mono">{id}</code>
              </h2>
              <span className={`badge-${riskTier.toLowerCase()}`} style={{ padding: '3px 10px', borderRadius: '12px', fontSize: '11px', fontWeight: '800' }}>
                {riskScore}/100 ({riskTier})
              </span>
            </div>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px' }}>
              Source PCAP: <span style={{ color: '#ffffff' }}>{pcapFile}</span> | Timestamp: {timestamp}
            </p>
          </div>
        </div>

        {/* 1. Timeline Visualizer inside inspector */}
        <TimelineVisualizer session={session} />

        {/* 2. Technical Parameters Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '16px', marginBottom: '24px' }}>
          
          <div style={{ background: 'rgba(255,255,255,0.03)', padding: '14px', borderRadius: '10px', border: '1px solid var(--border-subtle)' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              Handshake Protocol & Cipher
            </span>
            <div style={{ marginTop: '6px', fontSize: '13px', fontWeight: '600', color: '#ffffff' }}>
              {tlsVersion}
            </div>
            <div className="font-mono" style={{ fontSize: '11px', color: 'var(--accent-cyan)', marginTop: '2px' }}>
              {cipherSuite}
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginTop: '4px' }}>
              Key Exchange: {keyExchange} | PFS: {session.forwardSecrecy ? 'YES' : 'NO'}
            </div>
          </div>

          <div style={{ background: 'rgba(255,255,255,0.03)', padding: '14px', borderRadius: '10px', border: '1px solid var(--border-subtle)' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              X.509 Certificate Chain
            </span>
            {certificate ? (
              <>
                <div style={{ marginTop: '6px', fontSize: '13px', fontWeight: '600', color: certificate.isExpired ? 'var(--accent-rose)' : '#ffffff' }}>
                  {certificate.subject}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                  Issuer: {certificate.issuer}
                </div>
                <div style={{ fontSize: '11px', color: certificate.isExpired ? 'var(--accent-rose)' : 'var(--accent-emerald)', marginTop: '4px' }}>
                  Key: {certificate.keyType}-{certificate.keyLength} bit | {certificate.isExpired ? `Expired ${Math.abs(certificate.daysToExpiry)} days ago` : `Valid (${certificate.daysToExpiry} days remaining)`}
                </div>
              </>
            ) : (
              <div style={{ marginTop: '6px', fontSize: '12px', color: 'var(--text-dim)' }}>
                No X.509 certificate present in cleartext handshake stream.
              </div>
            )}
          </div>

          <div style={{ background: 'rgba(255,255,255,0.03)', padding: '14px', borderRadius: '10px', border: '1px solid var(--border-subtle)' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              AI Anomaly & Baseline Scoring
            </span>
            <div style={{ marginTop: '6px', fontSize: '14px', fontWeight: '700', color: aiAnomalyScore > 0.7 ? 'var(--accent-rose)' : 'var(--accent-emerald)' }}>
              Anomaly Score: {(aiAnomalyScore * 100).toFixed(0)}%
            </div>
            <p style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px', lineHeight: '1.4' }}>
              {aiExplanation}
            </p>
          </div>

        </div>

        {/* 3. Detected Findings List */}
        <div style={{ marginBottom: '24px' }}>
          <h3 style={{ fontSize: '14px', textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text-muted)', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <ShieldAlert size={16} color="var(--accent-amber)" />
            <span>Fired Rule Violations ({findings.length})</span>
          </h3>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {findings.map((f) => (
              <div key={f.id} style={{
                background: 'rgba(255, 255, 255, 0.02)',
                border: '1px solid var(--border-subtle)',
                borderLeft: `4px solid ${f.severity === 'CRITICAL' ? 'var(--accent-rose)' : f.severity === 'HIGH' ? 'var(--accent-amber)' : 'var(--accent-purple)'}`,
                borderRadius: '8px',
                padding: '14px'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '6px' }}>
                  <span style={{ fontSize: '14px', fontWeight: '700', color: '#ffffff' }}>
                    {f.title}
                  </span>
                  <span className="font-mono" style={{ fontSize: '11px', color: 'var(--accent-cyan)', background: 'rgba(6, 182, 212, 0.1)', padding: '2px 6px', borderRadius: '4px' }}>
                    {f.complianceRef}
                  </span>
                </div>

                <p style={{ fontSize: '12px', color: 'var(--text-main)', marginBottom: '8px' }}>
                  {f.description}
                </p>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', fontSize: '11px', background: 'rgba(0,0,0,0.2)', padding: '8px 12px', borderRadius: '6px' }}>
                  <div>
                    <strong style={{ color: 'var(--accent-rose)' }}>Impact: </strong>
                    <span style={{ color: 'var(--text-muted)' }}>{f.impact}</span>
                  </div>
                  <div>
                    <strong style={{ color: 'var(--accent-emerald)' }}>Remediation: </strong>
                    <span style={{ color: 'var(--text-muted)' }}>{f.remediation}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* 4. Raw Hex Snippet Preview */}
        <div>
          <h3 style={{ fontSize: '14px', textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text-muted)', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Terminal size={16} color="var(--accent-cyan)" />
            <span>Reconstructed PCAP TCP Byte Payload Snippet</span>
          </h3>
          <pre className="font-mono" style={{
            background: '#04070d',
            padding: '14px',
            borderRadius: '8px',
            border: '1px solid var(--border-subtle)',
            color: '#34d399',
            fontSize: '11px',
            overflowX: 'auto',
            lineHeight: '1.5'
          }}>
            {rawHexSnippet}
          </pre>
        </div>

      </div>
    </div>
  );
};
