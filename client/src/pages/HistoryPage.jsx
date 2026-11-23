import React, { useState } from 'react';
import { Search, Star, Trash2, Calendar } from 'lucide-react';
import { formatDate } from '../utils/formatters';
import StatusBadge from '../components/Common/StatusBadge';

const HistoryPage = ({
  history = [],
  onReopenScan,
  onToggleFavorite,
  onDeleteScan,
  onClearHistory
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [riskFilter, setRiskFilter] = useState('ALL');
  const [favOnly, setFavOnly] = useState(false);
  const [sortBy, setSortBy] = useState('date-desc'); // date-desc, date-asc, score-desc, score-asc
  
  // Destructive confirmations
  const [deleteConfirmId, setDeleteConfirmId] = useState(null);
  const [clearConfirm, setClearConfirm] = useState(false);

  // Filter history
  const filteredHistory = history.filter((item) => {
    // Search filter
    const matchesSearch = item.url.toLowerCase().includes(searchTerm.toLowerCase());
    
    // Risk filter
    let matchesRisk = true;
    if (riskFilter !== 'ALL') {
      if (riskFilter === 'THREAT') {
        matchesRisk = item.risk === 'CRITICAL' || item.risk === 'HIGH';
      } else {
        matchesRisk = item.risk === riskFilter;
      }
    }

    // Favorite filter
    const matchesFav = favOnly ? item.isFavorite : true;

    return matchesSearch && matchesRisk && matchesFav;
  });

  // Sort history
  const sortedHistory = [...filteredHistory].sort((a, b) => {
    if (sortBy === 'date-desc') {
      return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
    }
    if (sortBy === 'date-asc') {
      return new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
    }
    if (sortBy === 'score-desc') {
      return b.score - a.score;
    }
    if (sortBy === 'score-asc') {
      return a.score - b.score;
    }
    return 0;
  });

  const handleDeleteClick = (e, id) => {
    e.stopPropagation();
    setDeleteConfirmId(id);
  };

  const handleConfirmDelete = (e, id) => {
    e.stopPropagation();
    onDeleteScan(id);
    setDeleteConfirmId(null);
  };

  const handleCancelDelete = (e) => {
    e.stopPropagation();
    setDeleteConfirmId(null);
  };

  const handleClearClick = () => {
    setClearConfirm(true);
  };

  const handleConfirmClear = () => {
    onClearHistory();
    setClearConfirm(false);
  };

  return (
    <div className="page-wrapper">
      {/* Title Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 className="font-display" style={{ fontSize: '1.75rem', fontWeight: 700, margin: '0 0 0.5rem' }}>
            Local Scan Archive
          </h1>
          <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.9rem' }}>
            Review, filter, and reload previously captured security evaluations stored securely in your browser database.
          </p>
        </div>
        {history.length > 0 && !clearConfirm && (
          <button className="btn btn-danger" onClick={handleClearClick}>
            <Trash2 size={16} />
            <span>Clear History</span>
          </button>
        )}
      </div>

      {/* Clear All Confirmation Modal/Card */}
      {clearConfirm && (
        <div className="card" style={{ borderLeft: '4px solid var(--severity-critical)', backgroundColor: 'rgba(239, 68, 68, 0.05)' }}>
          <h3 className="font-display" style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--severity-critical)', marginBottom: '0.5rem' }}>
            Confirm Destructive Operation
          </h3>
          <p style={{ fontSize: '0.9rem', color: 'var(--color-text-secondary)' }}>
            Are you sure you want to permanently delete all {history.length} scans from your local history? This action cannot be undone.
          </p>
          <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1rem' }}>
            <button className="btn btn-danger" onClick={handleConfirmClear}>
              Yes, Clear All Scans
            </button>
            <button className="btn btn-secondary" onClick={() => setClearConfirm(false)}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Filters Box */}
      <div className="card">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem' }}>
          
          {/* Search */}
          <div style={{ position: 'relative' }}>
            <div className="detail-label" style={{ fontSize: '0.65rem', marginBottom: '0.35rem' }}>Search URL</div>
            <div style={{ position: 'relative' }}>
              <Search size={14} style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--color-text-muted)' }} />
              <input
                type="text"
                placeholder="Search by keyword..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="form-input"
                style={{ paddingLeft: '2.25rem', height: '2.5rem', fontSize: '0.85rem' }}
              />
            </div>
          </div>

          {/* Risk Level */}
          <div>
            <div className="detail-label" style={{ fontSize: '0.65rem', marginBottom: '0.35rem' }}>Filter by Threat Level</div>
            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
              className="form-input"
              style={{ height: '2.5rem', fontSize: '0.85rem', padding: '0 0.75rem', cursor: 'pointer' }}
            >
              <option value="ALL">All Scores</option>
              <option value="THREAT">Threats Only (Critical & High)</option>
              <option value="CRITICAL">Critical Risk</option>
              <option value="HIGH">High Risk</option>
              <option value="MEDIUM">Medium Risk</option>
              <option value="LOW">Low Risk</option>
              <option value="SAFE">Clean / Safe</option>
            </select>
          </div>

          {/* Favorites */}
          <div>
            <div className="detail-label" style={{ fontSize: '0.65rem', marginBottom: '0.35rem' }}>Favorite Filter</div>
            <button
              onClick={() => setFavOnly(!favOnly)}
              className={`btn ${favOnly ? 'btn-primary' : 'btn-secondary'}`}
              style={{ height: '2.5rem', fontSize: '0.85rem', width: '100%', display: 'flex', justifyContent: 'center' }}
            >
              <Star size={14} fill={favOnly ? "white" : "none"} />
              <span>{favOnly ? "Favorites Only" : "Show All Scans"}</span>
            </button>
          </div>

          {/* Sort By */}
          <div>
            <div className="detail-label" style={{ fontSize: '0.65rem', marginBottom: '0.35rem' }}>Sort order</div>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
              className="form-input"
              style={{ height: '2.5rem', fontSize: '0.85rem', padding: '0 0.75rem', cursor: 'pointer' }}
            >
              <option value="date-desc">Date: Newest First</option>
              <option value="date-asc">Date: Oldest First</option>
              <option value="score-desc">Score: Highest First</option>
              <option value="score-asc">Score: Lowest First</option>
            </select>
          </div>

        </div>
      </div>

      {/* History List/Table */}
      <div className="card">
        {sortedHistory.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '3.5rem 1rem', color: 'var(--color-text-secondary)' }}>
            <Calendar size={40} style={{ color: 'var(--color-text-muted)', marginBottom: '0.75rem' }} />
            <p style={{ fontWeight: 500, fontSize: '1.05rem' }}>No matching scans found.</p>
            <p style={{ fontSize: '0.85rem', color: 'var(--color-text-muted)', marginTop: '0.25rem' }}>
              {history.length === 0 ? 'Perform a URL check to record records.' : 'Adjust search terms or reset filters.'}
            </p>
          </div>
        ) : (
          <div className="table-container">
            <table className="sec-table">
              <thead>
                <tr>
                  <th style={{ width: '40px' }}>Fav</th>
                  <th>Target Scanned URL</th>
                  <th>Verdict</th>
                  <th>Score</th>
                  <th>Date Recorded</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {sortedHistory.map((item) => {
                  const isDeleting = deleteConfirmId === item.id;
                  
                  return (
                    <tr key={item.id}>
                      <td>
                        <button
                          onClick={(e) => { e.stopPropagation(); onToggleFavorite(item.id); }}
                          style={{ background: 'none', border: 'none', cursor: 'pointer', color: item.isFavorite ? 'var(--severity-medium)' : 'var(--color-text-muted)' }}
                        >
                          <Star size={16} fill={item.isFavorite ? 'var(--severity-medium)' : 'none'} />
                        </button>
                      </td>
                      <td style={{ maxWidth: '350px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>
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
                        {isDeleting ? (
                          <div style={{ display: 'inline-flex', gap: '0.25rem', alignItems: 'center' }}>
                            <span style={{ fontSize: '0.75rem', color: 'var(--severity-critical)', marginRight: '0.25rem' }}>Delete?</span>
                            <button
                              className="btn btn-danger"
                              style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                              onClick={(e) => handleConfirmDelete(e, item.id)}
                            >
                              Confirm
                            </button>
                            <button
                              className="btn btn-secondary"
                              style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                              onClick={handleCancelDelete}
                            >
                              Cancel
                            </button>
                          </div>
                        ) : (
                          <div style={{ display: 'inline-flex', gap: '0.5rem' }}>
                            <button
                              className="btn btn-primary"
                              style={{ padding: '0.35rem 0.75rem', fontSize: '0.8rem' }}
                              onClick={() => onReopenScan(item)}
                            >
                              View Report
                            </button>
                            <button
                              className="btn btn-icon"
                              style={{ padding: '0.35rem' }}
                              onClick={(e) => handleDeleteClick(e, item.id)}
                              title="Delete Record"
                            >
                              <Trash2 size={14} style={{ color: 'var(--severity-critical)' }} />
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default HistoryPage;
