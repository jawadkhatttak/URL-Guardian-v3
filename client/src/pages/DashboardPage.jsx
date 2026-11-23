import React, { useState } from 'react';
import { Search, ShieldAlert, ShieldCheck, Activity, AlertTriangle, ArrowRight, Star } from 'lucide-react';
import { formatDate } from '../utils/formatters';
import StatusBadge from '../components/Common/StatusBadge';

const DashboardPage = ({ history, onReopenScan, onNavigateToAnalyzer }) => {
  const [urlInput, setUrlInput] = useState('');

  const handleQuickSubmit = (e) => {
    e.preventDefault();
    const cleanUrl = urlInput.trim();
    if (cleanUrl) {
      onNavigateToAnalyzer(cleanUrl);
    }
  };

  // Compute stats from local scan history
  const totalScans = history.length;
  const criticalThreats = history.filter(s => s.risk === 'CRITICAL' || s.risk === 'HIGH').length;
  const warnings = history.filter(s => s.risk === 'MEDIUM').length;
  const cleanUrls = history.filter(s => s.risk === 'LOW' || s.risk === 'CLEAN' || s.risk === 'SAFE').length;
  
  const avgScore = totalScans > 0 
    ? Math.round(history.reduce((sum, s) => sum + s.score, 0) / totalScans) 
    : 0;

  // Last 5 scans
  const recentScans = history.slice(0, 5);

  return (
    <div className="page-wrapper">
      {/* Welcome Banner */}
      <div className="card" style={{ borderLeft: '4px solid var(--color-primary)' }}>
        <h1 className="font-display" style={{ fontSize: '1.75rem', fontWeight: 700, margin: '0 0 0.5rem' }}>
          URL Guardian Threat Intelligence Console
        </h1>
        <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.95rem' }}>
          Analyze suspicious URLs, inspect DNS records, review domain registry age, and correlate page structures to discover phishing and credential harvesting points.
        </p>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginTop: '0.9rem', flexWrap: 'wrap' }}>
          <span className="engine-chip"><span className="engine-dot" />Hybrid ML Scoring</span>
          <span className="version-chip">v3.0</span>
          <span className="topbar-root">24-feature model · SQLite archive</span>
        </div>
      </div>

      {/* Quick Search Action */}
      <div className="card">
        <div className="card-header">
          <h2 className="card-title">
            <Search size={18} style={{ color: 'var(--color-text-secondary)' }} />
            Quick Security Scan
          </h2>
        </div>
        <form onSubmit={handleQuickSubmit} className="analyzer-form">
          <div className="analyzer-input-container">
            <Search className="analyzer-input-icon" size={20} />
            <input
              type="text"
              placeholder="Enter full URL to analyze (e.g., https://example-phish.com/login)..."
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              className="form-input"
              required
            />
          </div>
          <button type="submit" className="btn btn-primary">
            Analyze URL
            <ArrowRight size={16} />
          </button>
        </form>
      </div>

      {/* Stats Summary Grid */}
      <div className="dashboard-grid">
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div className="detail-label">Scans Executed</div>
              <div className="font-display" style={{ fontSize: '2rem', fontWeight: 700, margin: '0.25rem 0' }}>
                {totalScans}
              </div>
              <span style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)' }}>
                Persistent local database
              </span>
            </div>
            <div className="btn-icon" style={{ backgroundColor: 'var(--color-primary-glow)', borderColor: 'var(--border-glow)' }}>
              <Activity size={20} style={{ color: 'var(--color-primary)' }} />
            </div>
          </div>
        </div>

        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div className="detail-label">Avg Risk Score</div>
              <div className="font-display" style={{ fontSize: '2rem', fontWeight: 700, margin: '0.25rem 0', color: avgScore > 60 ? 'var(--severity-high)' : avgScore > 30 ? 'var(--severity-medium)' : 'var(--severity-clean)' }}>
                {avgScore} / 100
              </div>
              <span style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)' }}>
                Overall scanned profile
              </span>
            </div>
            <div className="btn-icon" style={{ backgroundColor: avgScore > 50 ? 'var(--severity-high-bg)' : 'rgba(255,255,255,0.03)' }}>
              <AlertTriangle size={20} style={{ color: avgScore > 50 ? 'var(--severity-high)' : 'var(--color-text-secondary)' }} />
            </div>
          </div>
        </div>

        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div className="detail-label">Threats Flagged</div>
              <div className="font-display" style={{ fontSize: '2rem', fontWeight: 700, margin: '0.25rem 0', color: 'var(--severity-critical)' }}>
                {criticalThreats + warnings}
              </div>
              <span style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)' }}>
                {criticalThreats} critical, {warnings} high/med
              </span>
            </div>
            <div className="btn-icon" style={{ backgroundColor: 'var(--severity-critical-bg)', borderColor: 'var(--severity-critical-border)' }}>
              <ShieldAlert size={20} style={{ color: 'var(--severity-critical)' }} />
            </div>
          </div>
        </div>

        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div className="detail-label">Clean URLs Approved</div>
              <div className="font-display" style={{ fontSize: '2rem', fontWeight: 700, margin: '0.25rem 0', color: 'var(--severity-clean)' }}>
                {cleanUrls}
              </div>
              <span style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)' }}>
                No active threats verified
              </span>
            </div>
            <div className="btn-icon" style={{ backgroundColor: 'var(--severity-clean-bg)', borderColor: 'var(--severity-clean-border)' }}>
              <ShieldCheck size={20} style={{ color: 'var(--severity-clean)' }} />
            </div>
          </div>
        </div>
      </div>

      {/* Main Grid: Recent Activity Feed */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '1.5rem' }}>
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">
              <Activity size={18} style={{ color: 'var(--color-primary)' }} />
              Recent Scans
            </h2>
            <button className="btn btn-secondary btn-icon" onClick={() => onNavigateToAnalyzer('')} style={{ fontSize: '0.8rem', padding: '0.4rem 0.8rem' }}>
              View Analyzer
            </button>
          </div>

          {recentScans.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '2.5rem 1rem', color: 'var(--color-text-secondary)' }}>
              <ShieldCheck size={36} style={{ color: 'var(--color-text-muted)', marginBottom: '0.75rem' }} />
              <p style={{ fontWeight: 500 }}>No scans recorded in this browser.</p>
              <p style={{ fontSize: '0.85rem', color: 'var(--color-text-muted)' }}>Enter a URL above to perform your first automated analysis.</p>
            </div>
          ) : (
            <div className="table-container">
              <table className="sec-table">
                <thead>
                  <tr>
                    <th>Target URL</th>
                    <th>Risk Rating</th>
                    <th>Risk Score</th>
                    <th>Analysis Timestamp</th>
                    <th style={{ textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {recentScans.map((scan) => (
                    <tr key={scan.id}>
                      <td style={{ maxWidth: '350px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', fontFamily: 'var(--font-mono)' }}>
                        {scan.isFavorite && <Star size={12} fill="var(--severity-medium)" stroke="var(--severity-medium)" style={{ marginRight: '6px' }} />}
                        {scan.url}
                      </td>
                      <td>
                        <StatusBadge label={scan.risk} />
                      </td>
                      <td style={{ fontWeight: 600, color: scan.score > 60 ? 'var(--severity-critical)' : scan.score > 30 ? 'var(--severity-high)' : 'var(--severity-clean)' }}>
                        {scan.score} / 100
                      </td>
                      <td>{formatDate(scan.timestamp)}</td>
                      <td style={{ textAlign: 'right' }}>
                        <button
                          className="btn btn-primary"
                          style={{ padding: '0.35rem 0.75rem', fontSize: '0.8rem' }}
                          onClick={() => onReopenScan(scan)}
                        >
                          View Report
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default DashboardPage;
