import React from 'react';
import { Copy, Download, FileJson, Star, Shield, Clock, Check } from 'lucide-react';
import { formatDate } from '../../utils/formatters';
import { downloadJson } from '../../utils/exportUtils';
import ScoreGauge from '../Common/ScoreGauge';
import StatusBadge from '../Common/StatusBadge';
import UrlDetails from './UrlDetails';
import RuleFindings from './RuleFindings';
import DnsAnalysis from './DnsAnalysis';
import WhoisAnalysis from './WhoisAnalysis';
import HtmlAnalysis from './HtmlAnalysis';
import VirusTotalAnalysis from './VirusTotalAnalysis';
import CorrelationEngine from './CorrelationEngine';

const AnalysisResults = ({
  result,
  isFavorite,
  onToggleFavorite,
  onBack
}) => {
  const [copied, setCopied] = React.useState(false);

  const handleCopyUrl = () => {
    navigator.clipboard.writeText(result.url);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleExportJson = () => {
    downloadJson(result, result.details?.hostname, result.timestamp);
  };

  const handlePrintPdf = () => {
    window.print();
  };

  const activeFindingsCount = (result.findings?.url?.findings?.length || 0) + 
                              (result.findings?.html?.findings?.length || 0) +
                              (result.correlations?.length || 0) +
                              (result.findings?.virustotal?.positives || 0);

  // Describe how the score was produced (heuristic / ml / hybrid).
  const scoring = result.scoring;
  let scoreModeLabel = null;
  let scoreModeDetail = null;
  if (scoring && scoring.mode) {
    if (scoring.mode === 'hybrid') {
      scoreModeLabel = 'Hybrid Score';
      scoreModeDetail = `Heuristic ${scoring.heuristicScore} + ML ${scoring.mlScore}`;
    } else if (scoring.mode === 'ml') {
      scoreModeLabel = 'ML Score';
      scoreModeDetail = `Model confidence ${Math.round((scoring.mlProbability || 0) * 100)}%`;
    } else {
      scoreModeLabel = 'Heuristic Score';
      scoreModeDetail = 'Weighted rule engine';
    }
  }

  return (
    <div className="scan-results-container">
      {/* Action Header - Excluded from Print */}
      <div className="no-print" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <button className="btn btn-secondary" onClick={onBack}>
          ← Back to Scanner
        </button>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button 
            className="btn btn-secondary" 
            onClick={onToggleFavorite} 
            title={isFavorite ? "Remove from Favorites" : "Add to Favorites"}
          >
            <Star size={16} fill={isFavorite ? "var(--severity-medium)" : "none"} stroke={isFavorite ? "var(--severity-medium)" : "var(--color-text-secondary)"} />
            <span>{isFavorite ? "Favorited" : "Favorite"}</span>
          </button>
          <button className="btn btn-secondary" onClick={handleExportJson}>
            <FileJson size={16} />
            <span>Export JSON</span>
          </button>
          <button className="btn btn-primary" onClick={handlePrintPdf}>
            <Download size={16} />
            <span>Export PDF</span>
          </button>
        </div>
      </div>

      {/* PDF Header - Visible only when printing */}
      <div style={{ display: 'none' }} className="print-only">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '2px solid #000', paddingBottom: '10px', marginBottom: '20px' }}>
          <div>
            <h1 style={{ margin: 0, fontFamily: 'var(--font-display)', fontWeight: 800 }}>URL GUARDIAN ASSESSMENT REPORT</h1>
            <p style={{ margin: '4px 0 0', color: '#666' }}>Cybersecurity Automated Phishing & Metadata Analysis Profile</p>
          </div>
          <span style={{ fontSize: '10px', color: '#999' }}>Report Ref: UG-{new Date(result.timestamp).getTime()}</span>
        </div>
      </div>

      {/* Grid Row 1: Summary Banner */}
      <div className="card" style={{ marginBottom: '1.5rem', borderLeft: `5px solid var(--color-primary)` }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1.5rem' }}>
          <div style={{ flex: 1, minWidth: '280px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
              <Shield size={20} style={{ color: 'var(--color-primary)' }} />
              <StatusBadge label={result.risk} />
              <span className="no-print" style={{ color: 'var(--color-text-muted)', fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                <Clock size={12} />
                {formatDate(result.timestamp)}
              </span>
            </div>
            
            <h2 className="font-mono" style={{ fontSize: '1.25rem', wordBreak: 'break-all', fontWeight: 600, margin: '0.5rem 0' }}>
              {result.url}
            </h2>

            <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }} className="no-print">
              <button 
                onClick={handleCopyUrl} 
                className="btn btn-secondary" 
                style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}
              >
                {copied ? <Check size={12} style={{ color: 'var(--severity-clean)' }} /> : <Copy size={12} />}
                <span>{copied ? 'Copied' : 'Copy URL'}</span>
              </button>
            </div>

            <div style={{ padding: '0.75rem', backgroundColor: 'rgba(255,255,255,0.02)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-light)' }}>
              <div className="detail-label" style={{ fontSize: '0.7rem' }}>Platform Recommendation</div>
              <p style={{ fontSize: '0.88rem', color: 'var(--color-text-primary)', marginTop: '0.25rem' }}>
                {result.recommendation}
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minWidth: '150px' }}>
            <ScoreGauge score={result.score} risk={result.risk} />
            {scoreModeLabel && (
              <div className="score-caption">
                <span className="score-caption-mode">{scoreModeLabel}</span>
                <span className="score-caption-detail">{scoreModeDetail}</span>
              </div>
            )}
            <div style={{ textAlign: 'center', marginTop: '0.5rem', fontSize: '0.8rem', color: 'var(--color-text-secondary)' }}>
              {activeFindingsCount} security findings
            </div>
          </div>
        </div>
      </div>

      {/* Main Grid Details */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        
        {/* Correlations */}
        <CorrelationEngine correlations={result.correlations} />

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }} className="dashboard-grid-2">
          {/* Metadata */}
          <UrlDetails details={result.details} />
          {/* Rule engine */}
          <RuleFindings urlFindings={result.findings?.url} />
        </div>

        {/* Page Break for print layouts */}
        <div className="page-break" />

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }} className="dashboard-grid-2">
          {/* DNS */}
          <DnsAnalysis dnsData={result.findings?.dns} />
          {/* WHOIS */}
          <WhoisAnalysis whoisData={result.findings?.whois} />
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }} className="dashboard-grid-2">
          {/* HTML */}
          <HtmlAnalysis htmlData={result.findings?.html} />
          {/* VirusTotal */}
          <VirusTotalAnalysis vtData={result.findings?.virustotal} />
        </div>

      </div>

      {/* PDF Footer - Visible only when printing */}
      <div style={{ display: 'none' }} className="print-only">
        <div style={{ borderTop: '1px solid #cccccc', marginTop: '40px', paddingTop: '10px', display: 'flex', justifyContent: 'space-between', fontSize: '9px', color: '#666' }}>
          <span>URL Guardian Threat Intelligence Console Report</span>
          <span>Generated on: {new Date(result.timestamp).toLocaleDateString()}</span>
          <span>Page 1 of 1</span>
        </div>
      </div>
    </div>
  );
};

export default AnalysisResults;
