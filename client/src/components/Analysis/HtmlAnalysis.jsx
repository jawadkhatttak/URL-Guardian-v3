import React from 'react';
import { Code, Terminal } from 'lucide-react';

const HtmlAnalysis = ({ htmlData = {} }) => {
  const isHtmlAvailable = htmlData.success !== false;
  const findingsList = htmlData.findings || [];
  const riskScore = htmlData.riskScore || 0;

  return (
    <div className="card">
      <div className="card-header">
        <h2 className="card-title">
          <Code size={18} style={{ color: 'var(--color-primary)' }} />
          HTML Page Structural Inspection
        </h2>
        {isHtmlAvailable && (
          <span className={`badge ${riskScore > 60 ? 'badge-critical' : riskScore > 30 ? 'badge-high' : 'badge-clean'}`}>
            HTML Risk: {riskScore}/100
          </span>
        )}
      </div>

      {!isHtmlAvailable ? (
        <div style={{ textAlign: 'center', padding: '1rem', color: 'var(--color-text-secondary)' }}>
          <p style={{ fontSize: '0.9rem' }}>Page HTML structure scan failed or content is unreachable.</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div>
            <div className="detail-label" style={{ fontSize: '0.7rem', marginBottom: '0.5rem' }}>
              Document Parser Threat Verdict
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span className={`status-indicator ${htmlData.threatFound ? 'disconnected' : 'connected'}`} />
              <span style={{ fontSize: '0.95rem', fontWeight: 600 }}>
                {htmlData.threatFound ? 'Deceptive Structural Design Flagged' : 'No credential capture templates detected'}
              </span>
            </div>
          </div>

          <div>
            <div className="detail-label" style={{ fontSize: '0.7rem', marginBottom: '0.5rem' }}>
              Signals Scraped From Page Structure
            </div>
            {findingsList.length === 0 ? (
              <div style={{ fontSize: '0.85rem', color: 'var(--color-text-secondary)', padding: '0.5rem', border: '1px dashed var(--border-light)', borderRadius: 'var(--radius-sm)' }}>
                No active login prompts, suspicious forms, or credential harvest vectors detected on the parsed document.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {findingsList.map((finding, idx) => (
                  <div
                    key={idx}
                    style={{
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: '0.5rem',
                      padding: '0.65rem 0.75rem',
                      backgroundColor: 'rgba(255, 255, 255, 0.02)',
                      border: '1px solid var(--border-light)',
                      borderRadius: 'var(--radius-sm)',
                      fontSize: '0.88rem',
                      fontFamily: 'var(--font-mono)'
                    }}
                  >
                    <Terminal size={14} style={{ color: 'var(--severity-critical)', marginTop: '0.2rem', flexShrink: 0 }} />
                    <span style={{ color: 'var(--color-text-primary)' }}>{finding}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default HtmlAnalysis;
