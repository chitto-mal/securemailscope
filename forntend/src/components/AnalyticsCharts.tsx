import React from 'react';
import type { MailSession, SecurityPostureSummary } from '../types/pcap';
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Legend } from 'recharts';
import { BarChart3, PieChart as PieIcon } from 'lucide-react';

interface AnalyticsChartsProps {
  summary: SecurityPostureSummary;
  sessions: MailSession[];
}

export const AnalyticsCharts: React.FC<AnalyticsChartsProps> = ({ summary, sessions }) => {
  // Risk Distribution Data for Donut Chart
  const riskData = [
    { name: 'Critical', value: summary.criticalSessions, color: '#ef4444' },
    { name: 'High', value: summary.highSessions, color: '#f59e0b' },
    { name: 'Medium', value: summary.mediumSessions, color: '#8b5cf6' },
    { name: 'Low', value: summary.lowSessions, color: '#3b82f6' },
    { name: 'Secure', value: summary.secureSessions, color: '#10b981' },
  ].filter((d) => d.value > 0);

  // TLS Version Breakdown Data
  const tlsMap: Record<string, number> = {};
  sessions.forEach((s) => {
    tlsMap[s.tlsVersion] = (tlsMap[s.tlsVersion] || 0) + 1;
  });
  const tlsData = Object.keys(tlsMap).map((ver) => ({
    version: ver,
    count: tlsMap[ver],
  }));

  // Cipher Suite Breakdown Data
  const cipherMap: Record<string, number> = {};
  sessions.forEach((s) => {
    const cipherName = s.cipherSuite.length > 22 ? s.cipherSuite.substring(0, 22) + '...' : s.cipherSuite;
    cipherMap[cipherName] = (cipherMap[cipherName] || 0) + 1;
  });
  const cipherData = Object.keys(cipherMap).map((c) => ({
    cipher: c,
    count: cipherMap[c],
  }));

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '20px', marginBottom: '24px' }}>
      
      {/* Risk Severity Donut Chart */}
      <div className="glass-panel" style={{ padding: '20px' }}>
        <h3 style={{ fontSize: '14px', textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text-muted)', marginBottom: '14px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <PieIcon size={16} color="var(--accent-cyan)" />
          <span>Session Risk Tier Distribution</span>
        </h3>
        <div style={{ width: '100%', height: '220px' }}>
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={riskData}
                cx="50%"
                cy="50%"
                innerRadius={50}
                outerRadius={80}
                paddingAngle={4}
                dataKey="value"
              >
                {riskData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ background: '#111827', border: '1px solid var(--border-subtle)', borderRadius: '8px', color: '#fff' }}
              />
              <Legend verticalAlign="bottom" height={36} />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* TLS Version Bar Chart */}
      <div className="glass-panel" style={{ padding: '20px' }}>
        <h3 style={{ fontSize: '14px', textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text-muted)', marginBottom: '14px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <BarChart3 size={16} color="var(--accent-emerald)" />
          <span>TLS Version Adoption Breakdown</span>
        </h3>
        <div style={{ width: '100%', height: '220px' }}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={tlsData}>
              <XAxis dataKey="version" stroke="#9ca3af" fontSize={11} />
              <YAxis stroke="#9ca3af" fontSize={11} allowDecimals={false} />
              <Tooltip
                contentStyle={{ background: '#111827', border: '1px solid var(--border-subtle)', borderRadius: '8px', color: '#fff' }}
              />
              <Bar dataKey="count" fill="#06b6d4" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Cipher Suite Distribution Bar Chart */}
      <div className="glass-panel" style={{ padding: '20px' }}>
        <h3 style={{ fontSize: '14px', textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text-muted)', marginBottom: '14px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <BarChart3 size={16} color="var(--accent-purple)" />
          <span>Negotiated Cipher Suites</span>
        </h3>
        <div style={{ width: '100%', height: '220px' }}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={cipherData}>
              <XAxis dataKey="cipher" stroke="#9ca3af" fontSize={10} interval={0} />
              <YAxis stroke="#9ca3af" fontSize={11} allowDecimals={false} />
              <Tooltip
                contentStyle={{ background: '#111827', border: '1px solid var(--border-subtle)', borderRadius: '8px', color: '#fff' }}
              />
              <Bar dataKey="count" fill="#8b5cf6" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

    </div>
  );
};
