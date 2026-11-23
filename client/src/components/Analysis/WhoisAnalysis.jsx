import React from 'react';
import { Calendar } from 'lucide-react';
import { formatDate, formatDomainAge } from '../../utils/formatters';

const WhoisAnalysis = ({ whoisData = {} }) => {
  const isWhoisAvailable = whoisData.success !== false && (whoisData.creationDate || whoisData.registerName !== 'N/A');

  return (
    <div className="card">
      <div className="card-header">
        <h2 className="card-title">
          <Calendar size={18} style={{ color: 'var(--color-primary)' }} />
          WHOIS Registration Telemetry
        </h2>
      </div>

      {!isWhoisAvailable ? (
        <div style={{ textAlign: 'center', padding: '1rem', color: 'var(--color-text-secondary)' }}>
          <p style={{ fontSize: '0.9rem' }}>WHOIS registry telemetry unavailable or domain query failed.</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          
          {/* Domain Age Alert banner if age is young */}
          {typeof whoisData.domainAge === 'number' && whoisData.domainAge < 1 && (
            <div style={{ backgroundColor: 'var(--severity-critical-bg)', border: '1px solid var(--severity-critical-border)', borderRadius: 'var(--radius-sm)', padding: '0.75rem', fontSize: '0.85rem', color: 'var(--severity-critical)', display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
              <span>⚠️ <strong>Suspicious Domain Age:</strong> Registered less than a year ago ({formatDomainAge(whoisData.domainAge)}). Recently registered domains are highly correlated with phishing campaigns.</span>
            </div>
          )}

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
            <div>
              <div className="detail-label" style={{ fontSize: '0.7rem' }}>Domain Age</div>
              <div style={{ fontSize: '1rem', fontWeight: 600 }}>
                {whoisData.domainAge !== null ? formatDomainAge(whoisData.domainAge) : 'N/A'}
              </div>
              <span style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)' }}>
                {whoisData.daysSinceRegistration !== null ? `${whoisData.daysSinceRegistration} days active` : ''}
              </span>
            </div>

            <div>
              <div className="detail-label" style={{ fontSize: '0.7rem' }}>Domain Status</div>
              <div className="font-mono" style={{ fontSize: '0.9rem', color: 'var(--color-text-primary)' }}>
                {whoisData.status || 'N/A'}
              </div>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
            <div>
              <div className="detail-label" style={{ fontSize: '0.7rem' }}>Creation Date</div>
              <div style={{ fontSize: '0.88rem', color: 'var(--color-text-primary)' }}>
                {formatDate(whoisData.creationDate)}
              </div>
            </div>

            <div>
              <div className="detail-label" style={{ fontSize: '0.7rem' }}>Expiration Date</div>
              <div style={{ fontSize: '0.88rem', color: 'var(--color-text-primary)' }}>
                {formatDate(whoisData.expireDate)}
              </div>
            </div>
          </div>

          <div>
            <div className="detail-label" style={{ fontSize: '0.7rem' }}>Domain Registrar</div>
            <div style={{ fontSize: '0.9rem', color: 'var(--color-text-primary)' }}>
              {whoisData.registerName || 'N/A'}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default WhoisAnalysis;
