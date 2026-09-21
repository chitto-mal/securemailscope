import React from 'react';
import type { ForensicPcapDataset } from '../types/pcap';
import { X, Download, FileJson, Shield } from 'lucide-react';
import jsPDF from 'jspdf';

interface ReportExportModalProps {
  dataset: ForensicPcapDataset;
  onClose: () => void;
}

export const ReportExportModal: React.FC<ReportExportModalProps> = ({ dataset, onClose }) => {
  const { summary } = dataset;

  const exportJSON = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(dataset, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `SecureMailScope_Audit_${dataset.id}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const exportPDF = () => {
    const doc = new jsPDF();
    doc.setFont("helvetica", "bold");
    doc.setFontSize(18);
    doc.text("SecureMailScope - Cryptographic Security Audit", 14, 20);

    doc.setFontSize(10);
    doc.setFont("helvetica", "normal");
    doc.text(`Organization: NTRO / SIH 2026 | Date: ${new Date().toLocaleString()}`, 14, 28);
    doc.text(`Dataset: ${dataset.name}`, 14, 34);

    doc.setFontSize(14);
    doc.setFont("helvetica", "bold");
    doc.text(`Overall Cryptographic Posture Score: ${summary.overallScore} / 100 (${summary.postureTier})`, 14, 46);

    doc.setFontSize(11);
    doc.text("Sub-Score Breakdown:", 14, 56);
    let y = 64;
    Object.values(summary.subScores).forEach((sub) => {
      doc.setFont("helvetica", "normal");
      doc.text(`- ${sub.name}: ${sub.score} / ${sub.maxScore} (${sub.status})`, 20, y);
      y += 7;
    });

    y += 5;
    doc.setFont("helvetica", "bold");
    doc.text("Top Security Findings:", 14, y);
    y += 8;

    summary.topIssues.forEach((issue, idx) => {
      doc.setFont("helvetica", "bold");
      doc.text(`${idx + 1}. [${issue.severity}] ${issue.title}`, 18, y);
      y += 6;
      doc.setFont("helvetica", "normal");
      doc.text(`   Ref: ${issue.complianceRef}`, 18, y);
      y += 6;
      doc.text(`   Remediation: ${issue.remediation}`, 18, y);
      y += 8;
    });

    doc.save(`SecureMailScope_Audit_Report_${dataset.id}.pdf`);
  };

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
        maxWidth: '600px',
        padding: '28px',
        position: 'relative'
      }}>
        
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

        <div style={{ display: 'flex', alignItems: 'center', gap: '14px', marginBottom: '20px' }}>
          <div style={{
            background: 'linear-gradient(135deg, #10b981, #059669)',
            padding: '10px',
            borderRadius: '12px'
          }}>
            <Shield size={24} color="#ffffff" />
          </div>
          <div>
            <h2 style={{ fontSize: '18px', fontWeight: '800', color: '#ffffff' }}>
              Export Audit & Compliance Report
            </h2>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              Audit-ready report formatted according to NIST SP 800-52r2 and CERT-In compliance standards
            </p>
          </div>
        </div>

        {/* Dataset Summary Box */}
        <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '16px', borderRadius: '10px', border: '1px solid var(--border-subtle)', marginBottom: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Active PCAP:</span>
            <strong style={{ fontSize: '12px', color: '#ffffff' }}>{dataset.name}</strong>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Security Posture Score:</span>
            <strong className="font-mono" style={{ fontSize: '13px', color: 'var(--accent-emerald)' }}>
              {summary.overallScore} / 100 ({summary.postureTier})
            </strong>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Total Sessions Analyzed:</span>
            <strong style={{ fontSize: '12px', color: '#ffffff' }}>{summary.totalSessions} sessions</strong>
          </div>
        </div>

        {/* Action Buttons */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
          <button
            onClick={exportPDF}
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '8px',
              background: 'linear-gradient(135deg, #06b6d4, #3b82f6)',
              color: '#ffffff',
              border: 'none',
              borderRadius: '8px',
              padding: '12px',
              fontSize: '13px',
              fontWeight: '700',
              cursor: 'pointer',
              boxShadow: '0 4px 12px rgba(6, 182, 212, 0.3)'
            }}
          >
            <Download size={16} />
            <span>Download Audit PDF</span>
          </button>

          <button
            onClick={exportJSON}
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '8px',
              background: 'rgba(255, 255, 255, 0.08)',
              color: '#ffffff',
              border: '1px solid var(--border-subtle)',
              borderRadius: '8px',
              padding: '12px',
              fontSize: '13px',
              fontWeight: '600',
              cursor: 'pointer'
            }}
          >
            <FileJson size={16} color="var(--accent-emerald)" />
            <span>Export SIEM JSON</span>
          </button>
        </div>

      </div>
    </div>
  );
};
