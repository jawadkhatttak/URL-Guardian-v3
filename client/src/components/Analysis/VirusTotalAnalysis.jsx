import React from 'react';
import { ShieldAlert, Loader2 } from 'lucide-react';

const VirusTotalAnalysis = ({ vtData = {} }) => {
  const isVtAvailable = vtData.success !== false;
  
  // Check if status is QUEUED or PROCESSING
  const isPending = vtData.status === 'QUEUED' || vtData.status === 'PROCESSING' || vtData.status === 'IN_PROGRESS';

  return (
    <div className="card">
      <div className="card-header">
        <h2 className="card-title">
          <ShieldAlert size={18} style={{ color: 'var(--color-primary)' }} />
          VirusTotal Global Threat Intelligence
        </h2>
        {isVtAvailable && !isPending && (
          <span className="badge badge-low" style={{ borderColor: 'var(--border-light)', color: 'var(--color-text-secondary)' }}>
            Status: {vtData.status || 'COMPLETED'}
          </span>
        )}
      </div>

      {!isVtAvailable ? (
        <div style={{ textAlign: 'center', padding: '1rem', color: 'var(--color-text-secondary)' }}>
          <p style={{ fontSize: '0.9rem' }}>VirusTotal integration offline or API key limit reached.</p>
        </div>
      ) : isPending ? (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '1.5rem 1rem', textAlign: 'center', gap: '0.75rem' }}>
          <Loader2 size={24} className="scanning-pulse" style={{ color: 'var(--severity-medium)' }} />
          <div>
            <p style={{ fontSize: '0.92rem', fontWeight: 600, color: 'var(--severity-medium)' }}>
              Scan Analysis in Queue
            </p>
            <p style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)', marginTop: '0.25rem', maxWidth: '300px' }}>
              VirusTotal is performing an asynchronous threat scan. Detailed intelligence vendor reports will update once processing completes.
            </p>
          </div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
            <div>
              <div className="detail-label" style={{ fontSize: '0.7rem' }}>Detection Ratio</div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.25rem' }}>
                <span className="font-display" style={{ fontSize: '1.75rem', fontWeight: 700, color: vtData.positives > 0 ? 'var(--severity-critical)' : 'var(--severity-clean)' }}>
                  {vtData.positives || 0}
                </span>
                <span style={{ color: 'var(--color-text-muted)', fontSize: '0.9rem' }}>
                  / {vtData.totalScanners || 0} engines
                </span>
              </div>
            </div>

            <div>
              <div className="detail-label" style={{ fontSize: '0.7rem' }}>Domain Reputation</div>
              <div className="font-display" style={{ fontSize: '1.75rem', fontWeight: 700, color: vtData.reputation < 0 ? 'var(--severity-high)' : 'var(--color-text-primary)' }}>
                {vtData.reputation || 0}
              </div>
            </div>
          </div>

          <div>
            <div className="detail-label" style={{ fontSize: '0.7rem', marginBottom: '0.35rem' }}>Vendor Findings Summary</div>
            <div 
              style={{ 
                padding: '0.75rem', 
                backgroundColor: vtData.positives > 0 ? 'var(--severity-critical-bg)' : 'var(--severity-clean-bg)', 
                border: `1px solid ${vtData.positives > 0 ? 'var(--severity-critical-border)' : 'var(--severity-clean-border)'}`,
                borderRadius: 'var(--radius-sm)', 
                fontSize: '0.88rem',
                color: vtData.positives > 0 ? 'var(--severity-critical)' : 'var(--severity-clean)' 
              }}
            >
              {vtData.findings || (vtData.positives > 0 
                ? `Global Threat Alert: Flagged malicious by ${vtData.positives} engine vendors.` 
                : 'Clean Scan Profile: No security engines have marked this URL as malicious.')
              }
            </div>
          </div>

        </div>
      )}
    </div>
  );
};

export default VirusTotalAnalysis;
