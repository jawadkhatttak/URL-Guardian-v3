import React from 'react';
import { Info } from 'lucide-react';

const UrlDetails = ({ details = {} }) => {
  const items = [
    { label: 'Hostname', value: details.hostname },
    { label: 'Registered Domain', value: details.registeredDomain },
    { label: 'Subdomain', value: details.subdomain || '(None)' },
    { label: 'TLD', value: details.tld },
    { label: 'Protocol', value: details.protocol },
    { label: 'Port', value: details.port },
    { label: 'URL Length', value: `${details.urlLength || 0} characters` }
  ];

  return (
    <div className="card">
      <div className="card-header">
        <h2 className="card-title">
          <Info size={18} style={{ color: 'var(--color-primary)' }} />
          URL Breakdown & Metadata
        </h2>
      </div>
      <div className="detail-grid">
        {items.map((item, idx) => (
          <div key={idx} className="detail-item">
            <div className="detail-label">{item.label}</div>
            <div className="detail-value">{item.value || 'N/A'}</div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default UrlDetails;
