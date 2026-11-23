import React from 'react';
import { AlertTriangle, Layers } from 'lucide-react';
import StatusBadge from '../Common/StatusBadge';

const CorrelationEngine = ({ correlations = [] }) => {
  if (!correlations || correlations.length === 0) {
    return (
      <div className="card">
        <div className="card-header">
          <h2 className="card-title">
            <Layers size={18} style={{ color: 'var(--color-primary)' }} />
            Correlation Engine
          </h2>
        </div>
        <div style={{ textAlign: 'center', padding: '1.5rem', color: 'var(--color-text-secondary)' }}>
          <p style={{ fontSize: '0.9rem' }}>No correlation flags triggered. No cross-referenced threat indicators found.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="card" style={{ borderLeft: '4px solid var(--severity-high)' }}>
      <div className="card-header">
        <h2 className="card-title">
          <Layers size={18} style={{ color: 'var(--severity-high)' }} />
          Cross-Service Correlation Analysis
        </h2>
        <StatusBadge label="HIGH CONFIDENCE" />
      </div>

      <div className="correlation-list">
        {correlations.map((corr, idx) => {
          const isHighSev = corr.severity === 'high' || corr.severity === 'critical';
          return (
            <div
              key={corr.id || idx}
              className={`correlation-card severity-${corr.severity || 'medium'}`}
            >
              <div className="correlation-header">
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <AlertTriangle
                    size={16}
                    style={{ color: isHighSev ? 'var(--severity-critical)' : 'var(--severity-high)' }}
                  />
                  <span className="correlation-title">{corr.title || 'Threat Indicator'}</span>
                </div>
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <span className={`badge badge-${corr.severity || 'medium'}`} style={{ fontSize: '0.7rem' }}>
                    Severity: {corr.severity}
                  </span>
                  <span className="badge badge-low" style={{ fontSize: '0.7rem', color: 'var(--color-text-secondary)', borderColor: 'var(--border-light)' }}>
                    Confidence: {corr.confidence}
                  </span>
                </div>
              </div>

              {corr.evidence && corr.evidence.length > 0 && (
                <div>
                  <div className="detail-label" style={{ fontSize: '0.7rem', marginBottom: '0.35rem' }}>Correlated Evidence</div>
                  <ul className="evidence-list">
                    {corr.evidence.map((item, itemIdx) => (
                      <li key={itemIdx}>{item}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default CorrelationEngine;
