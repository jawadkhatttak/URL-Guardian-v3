import React from 'react';
import { Globe } from 'lucide-react';

const DnsAnalysis = ({ dnsData = {} }) => {
  const hasIpv4 = dnsData.ipv4 && dnsData.ipv4.length > 0;
  const hasIpv6 = dnsData.ipv6 && dnsData.ipv6.length > 0;
  const hasNs = dnsData.nameServers && dnsData.nameServers.length > 0;

  const isDnsAvailable = dnsData.success !== false && (hasIpv4 || hasIpv6 || hasNs);

  return (
    <div className="card">
      <div className="card-header">
        <h2 className="card-title">
          <Globe size={18} style={{ color: 'var(--color-primary)' }} />
          DNS Record Resolution
        </h2>
      </div>

      {!isDnsAvailable ? (
        <div style={{ textAlign: 'center', padding: '1rem', color: 'var(--color-text-secondary)' }}>
          <p style={{ fontSize: '0.9rem' }}>DNS records unavailable or query failed.</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div>
            <div className="detail-label" style={{ fontSize: '0.7rem' }}>Domain Resolved</div>
            <div className="font-mono" style={{ fontSize: '0.95rem', color: 'var(--color-text-primary)' }}>
              {dnsData.domain || 'N/A'}
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
            <div>
              <div className="detail-label" style={{ fontSize: '0.7rem' }}>IPv4 Addresses</div>
              {hasIpv4 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', marginTop: '0.25rem' }}>
                  {dnsData.ipv4.map((ip, idx) => (
                    <span key={idx} className="font-mono" style={{ fontSize: '0.85rem', color: 'var(--color-text-primary)' }}>
                      {ip}
                    </span>
                  ))}
                </div>
              ) : (
                <span className="font-mono" style={{ fontSize: '0.85rem', color: 'var(--color-text-muted)' }}>None found</span>
              )}
            </div>

            <div>
              <div className="detail-label" style={{ fontSize: '0.7rem' }}>IPv6 Addresses</div>
              {hasIpv6 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', marginTop: '0.25rem' }}>
                  {dnsData.ipv6.map((ip, idx) => (
                    <span key={idx} className="font-mono" style={{ fontSize: '0.85rem', color: 'var(--color-text-primary)' }}>
                      {ip}
                    </span>
                  ))}
                </div>
              ) : (
                <span className="font-mono" style={{ fontSize: '0.85rem', color: 'var(--color-text-muted)' }}>None found</span>
              )}
            </div>
          </div>

          <div>
            <div className="detail-label" style={{ fontSize: '0.7rem' }}>Authorized Name Servers (NS)</div>
            {hasNs ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', marginTop: '0.25rem' }}>
                {dnsData.nameServers.map((ns, idx) => (
                  <span key={idx} className="font-mono" style={{ fontSize: '0.85rem', color: 'var(--color-text-primary)' }}>
                    {ns}
                  </span>
                ))}
              </div>
            ) : (
              <span className="font-mono" style={{ fontSize: '0.85rem', color: 'var(--color-text-muted)' }}>None found</span>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default DnsAnalysis;
