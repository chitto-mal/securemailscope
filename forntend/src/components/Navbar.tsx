import React, { useRef } from 'react';
import { Shield, Upload, FileText, Activity, Layers } from 'lucide-react';
import type { ForensicPcapDataset, SecurityPostureSummary } from '../types/pcap';

interface NavbarProps {
  datasets: ForensicPcapDataset[];
  activeDatasetId: string;
  onSelectDataset: (id: string) => void;
  onUploadPcap: (file: File) => void;
  summary: SecurityPostureSummary;
  onOpenExportModal: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  datasets,
  activeDatasetId,
  onSelectDataset,
  onUploadPcap,
  summary,
  onOpenExportModal,
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      onUploadPcap(e.target.files[0]);
    }
  };

  const getTierClass = (tier: string) => {
    switch (tier) {
      case 'CRITICAL': return 'badge-critical';
      case 'HIGH': return 'badge-high';
      case 'MEDIUM': return 'badge-medium';
      case 'LOW': return 'badge-low';
      case 'SECURE': return 'badge-secure';
      default: return 'badge-medium';
    }
  };

  return (
    <header className="glass-panel" style={{ borderRadius: '0 0 16px 16px', borderTop: 'none', padding: '16px 28px', marginBottom: '24px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
        
        {/* Brand & Subtitle */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{
            background: 'linear-gradient(135deg, #06b6d4, #3b82f6)',
            padding: '10px',
            borderRadius: '12px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 15px rgba(6, 182, 212, 0.4)'
          }}>
            <Shield size={26} color="#ffffff" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <h1 style={{ fontSize: '22px', fontWeight: '800', letterSpacing: '-0.5px', color: '#ffffff' }}>
                SecureMailScope
              </h1>
              <span className="font-mono" style={{
                fontSize: '11px',
                background: 'rgba(6, 182, 212, 0.15)',
                color: '#06b6d4',
                padding: '2px 8px',
                borderRadius: '4px',
                border: '1px solid rgba(6, 182, 212, 0.3)',
                fontWeight: '600'
              }}>
                NTRO / SIH 2026
              </span>
            </div>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px' }}>
              Passive AI Cryptographic Posture Assessment for SMTP / IMAP / POP3 Traffic
            </p>
          </div>
        </div>

        {/* Live Status & Dataset Selector */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            background: 'rgba(255, 255, 255, 0.04)',
            padding: '6px 12px',
            borderRadius: '8px',
            border: '1px solid var(--border-subtle)',
            fontSize: '12px'
          }}>
            <span className="live-indicator"></span>
            <span style={{ color: 'var(--text-muted)' }}>Passive Capture Tap:</span>
            <strong style={{ color: '#ffffff' }}>PASSIVE FORENSIC MODE</strong>
          </div>

          {/* Dataset Selector */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Layers size={16} color="var(--accent-cyan)" />
            <select
              value={activeDatasetId}
              onChange={(e) => onSelectDataset(e.target.value)}
              style={{
                background: '#1f2937',
                color: '#f3f4f6',
                border: '1px solid var(--border-subtle)',
                borderRadius: '8px',
                padding: '8px 12px',
                fontSize: '13px',
                outline: 'none',
                cursor: 'pointer'
              }}
            >
              {datasets.map((ds) => (
                <option key={ds.id} value={ds.id}>
                  {ds.name}
                </option>
              ))}
            </select>
          </div>

          {/* Upload Button */}
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileChange}
            accept=".pcap,.pcapng,.json"
            style={{ display: 'none' }}
          />
          <button
            onClick={() => fileInputRef.current?.click()}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              background: 'rgba(255, 255, 255, 0.08)',
              color: '#ffffff',
              border: '1px solid var(--border-subtle)',
              borderRadius: '8px',
              padding: '8px 14px',
              fontSize: '13px',
              fontWeight: '600',
              cursor: 'pointer',
              transition: 'all 0.2s ease'
            }}
          >
            <Upload size={16} />
            <span>Upload PCAP</span>
          </button>

          {/* Export Report Button */}
          <button
            onClick={onOpenExportModal}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              background: 'linear-gradient(135deg, #10b981, #059669)',
              color: '#ffffff',
              border: 'none',
              borderRadius: '8px',
              padding: '8px 16px',
              fontSize: '13px',
              fontWeight: '700',
              cursor: 'pointer',
              boxShadow: '0 4px 12px rgba(16, 185, 129, 0.3)',
              transition: 'all 0.2s ease'
            }}
          >
            <FileText size={16} />
            <span>Audit Report</span>
          </button>

          {/* Posture Score Pill */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '6px 14px',
            borderRadius: '20px',
            fontSize: '13px',
            fontWeight: '700'
          }} className={getTierClass(summary.postureTier)}>
            <Activity size={16} />
            <span>Score: {summary.overallScore}/100</span>
            <span style={{ fontSize: '11px', textTransform: 'uppercase' }}>({summary.postureTier})</span>
          </div>

        </div>

      </div>
    </header>
  );
};
