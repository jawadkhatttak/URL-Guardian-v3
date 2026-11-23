import React, { useState } from 'react';
import { AlertCircle, ToggleLeft, ToggleRight } from 'lucide-react';
import { getSeverityClass } from '../../utils/formatters';

const RuleFindings = ({ urlFindings = {} }) => {
  const [showSuppressed, setShowSuppressed] = useState(false);
  const activeList = urlFindings.findings || [];
  const suppressedList = urlFindings.suppressedFindings || [];

  const totalActive = activeList.length;
  const totalSuppressed = suppressedList.length;

  if (totalActive === 0 && totalSuppressed === 0) {
    return (
      <div className="card">
        <div className="card-header">
          <h2 className="card-title">
            <AlertCircle size={18} style={{ color: 'var(--severity-clean)' }} />
            URL Rule Engine
          </h2>
        </div>
        <div style={{ textAlign: 'center', padding: '1.5rem', color: 'var(--color-text-secondary)' }}>
          <p style={{ fontSize: '0.9rem' }}>No rule violations detected in the URL string.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="card">
      <div className="card-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <AlertCircle size={18} style={{ color: totalActive > 0 ? 'var(--severity-high)' : 'var(--severity-clean)' }} />
          <h2 className="card-title">URL String Rule Engine</h2>
        </div>
        
        {totalSuppressed > 0 && (
          <button 
            onClick={() => setShowSuppressed(!showSuppressed)}
            className="btn btn-secondary"
            style={{ padding: '0.35rem 0.65rem', fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
          >
            {showSuppressed ? (
              <>
                <ToggleRight size={16} style={{ color: 'var(--color-primary)' }} />
                <span>Hide Suppressed ({totalSuppressed})</span>
              </>
            ) : (
              <>
                <ToggleLeft size={16} style={{ color: 'var(--color-text-secondary)' }} />
                <span>Show Suppressed ({totalSuppressed})</span>
              </>
            )}
          </button>
        )}
      </div>

      <div className="finding-list">
        {/* Active Findings */}
        {totalActive === 0 ? (
          <div style={{ fontSize: '0.88rem', color: 'var(--color-text-secondary)', padding: '0.5rem' }}>
            No active violations triggered.
          </div>
        ) : (
          activeList.map((item, idx) => (
            <div
              key={item.ruleId || idx}
              className={`finding-card ${getSeverityClass(item.severity)}`}
            >
              <div className="finding-header">
                <span className="finding-title">{item.title || 'Rule Triggered'}</span>
                <span className="badge badge-low" style={{ fontSize: '0.65rem', fontFamily: 'var(--font-mono)' }}>
                  ID: {item.ruleId}
                </span>
              </div>
              <p className="finding-description">{item.description}</p>
              {item.recommendation && (
                <div className="finding-rec">
                  <strong>Analyst Guidance:</strong> {item.recommendation}
                </div>
              )}
            </div>
          ))
        )}

        {/* Suppressed Findings */}
        {showSuppressed && totalSuppressed > 0 && (
          <div style={{ borderTop: '1px dashed var(--border-medium)', marginTop: '1rem', paddingTop: '1rem' }}>
            <h3 style={{ fontSize: '0.85rem', color: 'var(--color-text-secondary)', marginBottom: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Suppressed / Secondary Warnings
            </h3>
            <div className="finding-list">
              {suppressedList.map((item, idx) => (
                <div
                  key={`supp_${item.ruleId || idx}`}
                  className="finding-card suppressed-finding"
                  style={{ borderLeftColor: 'var(--color-text-muted)' }}
                >
                  <div className="finding-header">
                    <span className="finding-title">{item.title || 'Suppressed Rule'}</span>
                    <span className="badge badge-low" style={{ fontSize: '0.65rem', fontFamily: 'var(--font-mono)' }}>
                      ID: {item.ruleId}
                    </span>
                  </div>
                  <p className="finding-description">{item.description}</p>
                  {item.recommendation && (
                    <div className="finding-rec">
                      <strong>Note:</strong> {item.recommendation}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default RuleFindings;
