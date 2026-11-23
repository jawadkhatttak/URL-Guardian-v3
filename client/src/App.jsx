import React, { useState } from 'react';
import Sidebar from './components/Navigation/Sidebar';
import DashboardPage from './pages/DashboardPage';
import AnalyzerPage from './pages/AnalyzerPage';
import HistoryPage from './pages/HistoryPage';
import ReportsPage from './pages/ReportsPage';
import { useScanHistory } from './hooks/useScanHistory';
import { useApiStatus } from './hooks/useApiStatus';

const SECTION_TITLES = {
  dashboard: 'Dashboard',
  analyzer: 'URL Analyzer',
  history: 'Scan History',
  reports: 'Reports',
};

function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [analyzerPrefillUrl, setAnalyzerPrefillUrl] = useState('');
  const [openedScan, setOpenedScan] = useState(null);

  const apiStatus = useApiStatus();

  // Hook for scan persistence (SQLite-backed via the API)
  const {
    history,
    addScan,
    toggleFavorite,
    deleteScan,
    clearHistory
  } = useScanHistory();

  // Load a historical scan report inside the Analyzer tab
  const handleReopenScan = (scanItem) => {
    setOpenedScan(scanItem);
    setAnalyzerPrefillUrl(''); // Clear any prefilled input URL
    setActiveTab('analyzer');
  };

  // Prefill a URL and trigger a scan in the Analyzer tab
  const handleNavigateToAnalyzer = (url) => {
    setAnalyzerPrefillUrl(url);
    setOpenedScan(null); // Clear any currently opened static scan report
    setActiveTab('analyzer');
  };

  const renderActivePage = () => {
    switch (activeTab) {
      case 'dashboard':
        return (
          <DashboardPage
            history={history}
            onReopenScan={handleReopenScan}
            onNavigateToAnalyzer={handleNavigateToAnalyzer}
          />
        );
      case 'analyzer':
        return (
          <AnalyzerPage
            initialUrl={analyzerPrefillUrl}
            openedScan={openedScan}
            onClearOpenedScan={() => {
              setOpenedScan(null);
              setAnalyzerPrefillUrl('');
            }}
            history={history}
            onAddScan={addScan}
            onToggleFavorite={toggleFavorite}
          />
        );
      case 'history':
        return (
          <HistoryPage
            history={history}
            onReopenScan={handleReopenScan}
            onToggleFavorite={toggleFavorite}
            onDeleteScan={deleteScan}
            onClearHistory={clearHistory}
          />
        );
      case 'reports':
        return (
          <ReportsPage
            history={history}
            onReopenScan={handleReopenScan}
          />
        );
      default:
        return (
          <DashboardPage
            history={history}
            onReopenScan={handleReopenScan}
            onNavigateToAnalyzer={handleNavigateToAnalyzer}
          />
        );
    }
  };

  return (
    <div className="app-container">
      {/* Navigation Sidebar */}
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />

      {/* Content panel */}
      <main className="main-content">
        {/* Console status bar */}
        <header className="app-topbar no-print">
          <div className="topbar-breadcrumb">
            <span className="topbar-root">Console</span>
            <span className="topbar-sep">/</span>
            <span className="topbar-current">{SECTION_TITLES[activeTab] || 'Dashboard'}</span>
          </div>

          <div className="topbar-status">
            <span className={`status-pill is-${apiStatus}`}>
              <span className="status-dot" />
              {apiStatus === 'online' ? 'Systems Online' : apiStatus === 'offline' ? 'Systems Offline' : 'Connecting'}
            </span>
            <span className="topbar-divider" />
            <span className="engine-chip" title="Heuristic + machine-learning hybrid scoring">
              <span className="engine-dot" />
              Hybrid Engine
            </span>
            <span className="version-chip">v3.0</span>
          </div>
        </header>

        {renderActivePage()}
      </main>
    </div>
  );
}

export default App;