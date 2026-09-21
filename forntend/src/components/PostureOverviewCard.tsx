import React from 'react';
import type { SecurityPostureSummary, PostureSubScore } from '../types/pcap';
import { ShieldAlert } from 'lucide-react';

interface PostureOverviewCardProps {
  summary: SecurityPostureSummary;
}

export const PostureOverviewCard: React.FC<PostureOverviewCardProps> = ({ summary }) => {
  const { overallScore, postureTier, subScores, remediationPriority } = summary;

  const getGaugeColor = (score: number) => {
    if (score < 40) return 'var(--accent-rose)';
    if (score < 60) return 'var(--accent-amber)';
    if (score < 80) return 'var(--accent-purple)';
    return 'var(--accent-emerald)';
  };

  const circumference = 2 * Math.PI * 46;
  const strokeDashoffset = circumference - (overallScore / 100) * circumference;

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '20px', marginBottom: '24px' }}>
      
      {/* 1. Main Score Gauge & Tier Card */}
      <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between', position: 'relative', overflow: 'hidden' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <h3 style={{ fontSize: '14px', textTransform: 'uppercase', letterSpacing: '1px', color: 'var(--text-muted)', fontWeight: '600' }}>
              Cryptographic Posture Score
            </h3>
            <p style={{ fontSize: '12px', color: 'var(--text-dim)', marginTop: '2px' }}>
              NIST SP 800-52r2 & RFC 8996 Hybrid Risk Fusion
            </p>
          </div>
          <span className={`badge-${postureTier.toLowerCase()}`} style={{ padding: '4px 10px', borderRadius: '12px', fontSize: '11px', fontWeight: '800' }}>
            {postureTier}
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '20px 0' }}>
          <div style={{ position: 'relative', width: '130px', height: '130px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <svg width="130" height="130" viewBox="0 0 100 100" style={{ transform: 'rotate(-90deg)' }}>
              <circle cx="50" cy="50" r="46" fill="transparent" stroke="rgba(255,255,255,0.06)" strokeWidth="8" />
              <circle
                cx="50" cy="50" r="46"
                fill="transparent"
                stroke={getGaugeColor(overallScore)}
                strokeWidth="8"
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                style={{ transition: 'stroke-dashoffset 1s ease-in-out' }}
              />
            </svg>
            <div style={{ position: 'absolute', textAlign: 'center' }}>
              <span className="font-mono" style={{ fontSize: '32px', fontWeight: '800', color: '#ffffff' }}>
                {overallScore}
              </span>
              <span style={{ fontSize: '12px', color: 'var(--text-muted)', display: 'block' }}>/100</span>
            </div>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', paddingTop: '12px', borderTop: '1px solid var(--border-subtle)' }}>
          <div style={{ background: 'rgba(255,255,255,0.02)', padding: '8px 12px', borderRadius: '8px' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Analyzed Sessions</span>
            <div className="font-mono" style={{ fontSize: '16px', fontWeight: '700', color: '#ffffff' }}>{summary.totalSessions}</div>
          </div>
          <div style={{ background: 'rgba(255,255,255,0.02)', padding: '8px 12px', borderRadius: '8px' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Critical / High Risk</span>
            <div className="font-mono" style={{ fontSize: '16px', fontWeight: '700', color: summary.criticalSessions + summary.highSessions > 0 ? 'var(--accent-rose)' : 'var(--accent-emerald)' }}>
              {summary.criticalSessions + summary.highSessions}
            </div>
          </div>
        </div>
      </div>

      {/* 2. Sub-score Categories Breakdown */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <h3 style={{ fontSize: '14px', textTransform: 'uppercase', letterSpacing: '1px', color: 'var(--text-muted)', fontWeight: '600', marginBottom: '16px' }}>
          Decomposed Sub-Scores
        </h3>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {Object.values(subScores).map((sub: PostureSubScore, idx) => (
            <div key={idx} style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
                <span style={{ color: 'var(--text-main)', fontWeight: '500' }}>{sub.name}</span>
                <span className="font-mono" style={{ fontWeight: '700', color: sub.status === 'CRITICAL' ? 'var(--accent-rose)' : sub.status === 'GOOD' || sub.status === 'EXCELLENT' ? 'var(--accent-emerald)' : 'var(--accent-amber)' }}>
                  {sub.score} / {sub.maxScore}
                </span>
              </div>
              <div style={{ width: '100%', height: '6px', background: 'rgba(255,255,255,0.06)', borderRadius: '3px', overflow: 'hidden' }}>
                <div style={{
                  height: '100%',
                  width: `${(sub.score / sub.maxScore) * 100}%`,
                  background: sub.status === 'CRITICAL' ? 'var(--accent-rose)' : sub.status === 'GOOD' || sub.status === 'EXCELLENT' ? 'var(--accent-emerald)' : 'var(--accent-amber)',
                  borderRadius: '3px',
                  transition: 'width 0.8s ease'
                }}></div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* 3. Top Security Issues & Actionable Remediation */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <h3 style={{ fontSize: '14px', textTransform: 'uppercase', letterSpacing: '1px', color: 'var(--text-muted)', fontWeight: '600', marginBottom: '14px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <ShieldAlert size={16} color="var(--accent-amber)" />
          <span>Priority Remediation Checklist</span>
        </h3>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {remediationPriority.map((item, idx) => (
            <div key={idx} style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: '10px',
              background: 'rgba(255, 255, 255, 0.03)',
              padding: '10px 12px',
              borderRadius: '8px',
              borderLeft: `3px solid ${idx === 0 && summary.criticalSessions > 0 ? 'var(--accent-rose)' : 'var(--accent-cyan)'}`
            }}>
              <span className="font-mono" style={{ fontSize: '12px', color: 'var(--accent-cyan)', fontWeight: '700' }}>
                0{idx + 1}.
              </span>
              <span style={{ fontSize: '12px', color: '#e5e7eb', lineHeight: '1.4' }}>
                {item}
              </span>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
};
