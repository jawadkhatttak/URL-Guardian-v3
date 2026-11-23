import React from 'react';
import { FileText, Download, FileJson, Shield, Star } from 'lucide-react';
import { formatDate } from '../utils/formatters';
import { downloadJson } from '../utils/exportUtils';
import StatusBadge from '../components/Common/StatusBadge';

const ReportsPage = ({ history = [], onReopenScan }) => {

  const handleExportJson = (e, item) => {
    e.stopPropagation();
    downloadJson(item.fullData, item.fullData?.details?.hostname, item.timestamp);
  };

  const handleExportPdf = (e, item) => {
    e.stopPropagation();
    // Reopen scan which will load it into active analyzer view, and then
    // trigger print layout by setting a small timeout or letting the user trigger it.
    // To make it seamless, we open the scan results so they can view and print it.
    onReopenScan(item);
    setTimeout(() => {
      window.print();
    }, 300);
  };

  return (
    <div className="page-wrapper">
      {/* Title */}
      <div>
        <h1 className="font-display" style={{ fontSize: '1.75rem', fontWeight: 700, margin: '0 0 0.5rem' }}>
          Threat Assessment Reports
        </h1>
        <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.9rem' }}>
          Access, export, and download comprehensive automated reports for any analyzed target in standard JSON telemetry format or print-ready PDF layouts.
        </p>
      </div>

      {/* Reports Grid */}
      <div className="card">
        <div className="card-header">
          <h2 className="card-title">
            <FileText size={18} style={{ color: 'var(--color-primary)' }} />
            Security Assessment Ledger
          </h2>
        </div>

        {history.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '3.5rem 1rem', color: 'var(--color-text-secondary)' }}>
            <FileText size={40} style={{ color: 'var(--color-text-muted)', marginBottom: '0.75rem' }} />
            <p style={{ fontWeight: 500 }}>No assessment records available.</p>
            <p style={{ fontSize: '0.85rem', color: 'var(--color-text-muted)', marginTop: '0.25rem' }}>
              Run URL analyses to automatically compile assessment logs.
            </p>
          </div>
        ) : (
          <div className="table-container">
            <table className="sec-table">
              <thead>
                <tr>
                  <th>Target URL</th>
                  <th>Risk Level</th>
                  <th>Risk Score</th>
                  <th>Date Generated</th>
                  <th style={{ textAlign: 'right' }}>Document Exports</th>
                </tr>
              </thead>
              <tbody>
                {history.map((item) => (
                  <tr key={item.id} style={{ cursor: 'pointer' }} onClick={() => onReopenScan(item)}>
                    <td style={{ maxWidth: '300px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>
                      {item.isFavorite && <Star size={12} fill="var(--severity-medium)" stroke="var(--severity-medium)" style={{ marginRight: '6px', display: 'inline' }} />}
                      {item.url}
                    </td>
                    <td>
                      <StatusBadge label={item.risk} />
                    </td>
                    <td style={{ fontWeight: 600, color: item.score > 60 ? 'var(--severity-critical)' : item.score > 30 ? 'var(--severity-high)' : 'var(--severity-clean)' }}>
                      {item.score} / 100
                    </td>
                    <td style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)' }}>
                      {formatDate(item.timestamp)}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <div style={{ display: 'inline-flex', gap: '0.5rem' }} onClick={(e) => e.stopPropagation()}>
                        <button
                          className="btn btn-secondary"
                          style={{ padding: '0.35rem 0.65rem', fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}
                          onClick={(e) => handleExportJson(e, item)}
                          title="Export raw JSON telemetry"
                        >
                          <FileJson size={13} />
                          <span>JSON</span>
                        </button>
                        <button
                          className="btn btn-primary"
                          style={{ padding: '0.35rem 0.65rem', fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}
                          onClick={(e) => handleExportPdf(e, item)}
                          title="Generate PDF Assessment Report"
                        >
                          <Download size={13} />
                          <span>PDF</span>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Info card */}
      <div className="card" style={{ borderLeft: '4px solid var(--color-primary)' }}>
        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-start' }}>
          <Shield size={20} style={{ color: 'var(--color-primary)', marginTop: '0.1rem' }} />
          <div>
            <h4 className="font-display" style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '0.25rem' }}>
              Standard Compliance Reporting
            </h4>
            <p style={{ fontSize: '0.85rem', color: 'var(--color-text-secondary)' }}>
              Reports generated by URL Guardian combine heuristics from URL pattern rules, registered active DNS resolvers, historical registry WHOIS timelines, scraped page HTML form contexts, and VirusTotal scanner databases. Use these exports for SOC alerts, record tracking, or security auditing audits.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ReportsPage;
