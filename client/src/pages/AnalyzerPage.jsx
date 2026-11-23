import React, { useState, useEffect } from 'react';
import { Search, ShieldAlert, Loader2, RefreshCw, AlertTriangle, ShieldCheck } from 'lucide-react';
import { scanUrl } from '../api/guardianApi';
import AnalysisResults from '../components/Analysis/AnalysisResults';

// Static copy shown while a scan is running
const SCAN_PHASES = [
  'Connecting to Guardian Intelligence Endpoint...',
  'Performing DNS server query & resolving IP maps...',
  'Fetching domain registration details & WHOIS status...',
  'Analyzing HTML structure, looking for form/credential harvest forms...',
  'Checking VirusTotal reputations & global security engines...',
  'Correlating telemetry layers and generating threat verdict...'
];

const AnalyzerPage = ({
  initialUrl = '',
  openedScan = null,
  onClearOpenedScan,
  history = [],
  onAddScan,
  onToggleFavorite
}) => {
  const [url, setUrl] = useState(initialUrl);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [activeScan, setActiveScan] = useState(openedScan);
  
  // Loading phases animation
  const [scanPhase, setScanPhase] = useState(0);

  // Effect to scan immediately if initialUrl is passed
  useEffect(() => {
    if (initialUrl) {
      setUrl(initialUrl);
      handleScan(initialUrl);
    }
    // Intentionally runs only when initialUrl changes, not on every handleScan re-creation
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialUrl]);

  // Effect to sync opened scan from history
  useEffect(() => {
    if (openedScan) {
      setActiveScan(openedScan);
    }
  }, [openedScan]);

  // Cycle through loading phases when loading is true
  useEffect(() => {
    let interval;
    if (loading) {
      setScanPhase(0);
      interval = setInterval(() => {
        setScanPhase((prev) => (prev < SCAN_PHASES.length - 1 ? prev + 1 : prev));
      }, 1500);
    }
    return () => clearInterval(interval);
  }, [loading]);

  const validateUrl = (string) => {
    let clean = string.trim();
    if (!clean) return false;
    
    // Add protocol if missing to make it a valid URL format for verification
    if (!/^https?:\/\//i.test(clean)) {
      clean = 'http://' + clean;
    }
    
    try {
      new URL(clean);
      return true;
    } catch {
      return false;
    }
  };

  const handleScan = async (targetUrl) => {
    const cleanUrl = targetUrl || url.trim();
    if (!cleanUrl) return;

    if (!validateUrl(cleanUrl)) {
      setError('Please enter a valid URL (e.g. example.com or https://example.com).');
      return;
    }

    setLoading(true);
    setError(null);
    setActiveScan(null);
    if (onClearOpenedScan) onClearOpenedScan();

    try {
      const data = await scanUrl(cleanUrl);
      // Save scan to history
      const savedEntry = onAddScan(data);
      // Set active scan
      setActiveScan(savedEntry);
    } catch (err) {
      console.error(err);
      setError(err.message || 'An unexpected error occurred while scanning.');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    handleScan();
  };

  const handleBack = () => {
    setActiveScan(null);
    if (onClearOpenedScan) onClearOpenedScan();
    setUrl('');
  };

  // Find if active scan is favorited in history list
  const getIsFavorite = () => {
    if (!activeScan) return false;
    const match = history.find((h) => h.url === activeScan.url);
    return match ? match.isFavorite : false;
  };

  const triggerToggleFavorite = () => {
    if (!activeScan) return;
    onToggleFavorite(activeScan.id);
  };

  if (activeScan) {
    return (
      <div className="page-wrapper">
        <AnalysisResults
          result={activeScan.fullData}
          isFavorite={getIsFavorite()}
          onToggleFavorite={triggerToggleFavorite}
          onBack={handleBack}
        />
      </div>
    );
  }

  return (
    <div className="page-wrapper">
      {/* Title */}
      <div className="no-print">
        <h1 className="font-display" style={{ fontSize: '1.75rem', fontWeight: 700, margin: '0 0 0.5rem' }}>
          URL Analyzer
        </h1>
        <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.9rem' }}>
          Input any URL string below to run an automated check against brand spoofing rules, DNS settings, registry longevity, and HTML composition.
        </p>
      </div>

      {/* Search Bar */}
      <div className="card no-print">
        <form onSubmit={handleSubmit} className="analyzer-form">
          <div className="analyzer-input-container">
            <Search className="analyzer-input-icon" size={20} />
            <input
              type="text"
              placeholder="Enter full target URL (e.g., netflix-suporte.dynv6.net/login.html)..."
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="form-input"
              disabled={loading}
              required
            />
          </div>
          <button type="submit" className="btn btn-primary" disabled={loading}>
            {loading ? (
              <>
                <Loader2 size={16} className="scanning-pulse" />
                <span>Analyzing...</span>
              </>
            ) : (
              <span>Scan Target</span>
            )}
          </button>
        </form>
      </div>

      {/* Loading State */}
      {loading && (
        <div className="card no-print" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '3rem 1.5rem', gap: '1.5rem' }}>
          <div style={{ position: 'relative', width: '80px', height: '80px' }}>
            <div style={{ 
              position: 'absolute', 
              width: '100%', 
              height: '100%', 
              border: '4px solid var(--color-primary-glow)', 
              borderTopColor: 'var(--color-primary)', 
              borderRadius: '50%',
              animation: 'spin 1.2s linear infinite'
            }} />
            <ShieldAlert size={32} style={{ color: 'var(--color-primary)', position: 'absolute', top: '24px', left: '24px' }} className="scanning-pulse" />
          </div>
          
          <div style={{ textAlign: 'center' }}>
            <h3 className="font-display" style={{ fontSize: '1.1rem', fontWeight: 600, marginBottom: '0.5rem' }}>
              Threat Assessment in Progress
            </h3>
            <p className="font-mono" style={{ fontSize: '0.85rem', color: 'var(--color-primary)' }}>
              {SCAN_PHASES[scanPhase]}
            </p>
          </div>

          {/* Loading Skeletons */}
          <div style={{ width: '100%', maxWidth: '600px', display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '1rem' }}>
            <div className="skeleton skeleton-title" style={{ width: '40%', margin: '0 auto 0.5rem' }} />
            <div className="skeleton skeleton-text" />
            <div className="skeleton skeleton-text" style={{ width: '85%', margin: '0 auto' }} />
          </div>
        </div>
      )}

      {/* Error state */}
      {error && !loading && (
        <div className="card no-print" style={{ borderLeft: '4px solid var(--severity-critical)' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem' }}>
            <AlertTriangle size={20} style={{ color: 'var(--severity-critical)', marginTop: '0.1rem' }} />
            <div>
              <h3 className="font-display" style={{ fontSize: '1.05rem', fontWeight: 600, color: 'var(--severity-critical)', marginBottom: '0.25rem' }}>
                Scan Engine Error
              </h3>
              <p style={{ fontSize: '0.88rem', color: 'var(--color-text-secondary)' }}>
                {error}
              </p>
              <button 
                onClick={() => handleScan(url)}
                className="btn btn-secondary"
                style={{ marginTop: '0.75rem', padding: '0.35rem 0.75rem', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}
              >
                <RefreshCw size={12} />
                <span>Retry Connection</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Idle Instruction State */}
      {!loading && !error && !activeScan && (
        <div className="card no-print" style={{ textAlign: 'center', padding: '4rem 2rem', borderStyle: 'dashed', borderWidth: '1px' }}>
          <div style={{ display: 'inline-flex', padding: '1rem', borderRadius: '50%', backgroundColor: 'var(--color-primary-glow)', marginBottom: '1.25rem' }}>
            <ShieldCheck size={36} style={{ color: 'var(--color-primary)' }} />
          </div>
          <h2 className="font-display" style={{ fontSize: '1.25rem', fontWeight: 600, marginBottom: '0.5rem' }}>
            Ready for Input
          </h2>
          <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.9rem', maxWidth: '420px', margin: '0 auto' }}>
            Enter a fully-qualified domain or login URL above. URL Guardian will perform passive scans and report DNS records, WHOIS registration flags, page content structures, and VirusTotal reputation values.
          </p>
        </div>
      )}

    </div>
  );
};

export default AnalyzerPage;
