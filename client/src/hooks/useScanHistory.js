import { useState, useEffect, useCallback } from 'react';
import {
  getScans,
  toggleScanFavorite,
  deleteScanRequest,
  clearScansRequest,
} from '../api/guardianApi';

/**
 * Scan history backed by the server (SQLite via the /api/v1/scans endpoints).
 *
 * The public interface is unchanged from the localStorage version
 * (history, addScan, toggleFavorite, deleteScan, clearHistory) so the rest of
 * the app keeps working, but the source of truth is now the backend database.
 */
export const useScanHistory = () => {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const scans = await getScans();
      setHistory(scans);
    } catch (err) {
      setError(err.message || 'Failed to load scan history.');
    } finally {
      setLoading(false);
    }
  }, []);

  // Load history from the server on mount.
  useEffect(() => {
    refresh();
  }, [refresh]);

  /**
   * Record a freshly completed scan (already persisted by the backend during
   * POST /api/v1/analyze). Adds the returned data to local state so the UI
   * reflects it immediately without a refetch.
   */
  const addScan = (scanData) => {
    const entry = {
      id: scanData.id ?? `local_${Date.now()}`,
      url: scanData.url,
      timestamp: scanData.timestamp || new Date().toISOString(),
      score: scanData.score,
      risk: scanData.risk,
      isFavorite: scanData.isFavorite === true,
      fullData: scanData,
    };

    setHistory((prev) => [entry, ...prev.filter((item) => item.id !== entry.id)]);
    return entry;
  };

  /**
   * Toggle a scan's favorite flag on the server, then sync local state.
   */
  const toggleFavorite = async (id) => {
    // Optimistic update for a snappy UI.
    setHistory((prev) =>
      prev.map((item) =>
        item.id === id ? { ...item, isFavorite: !item.isFavorite } : item
      )
    );

    try {
      const updated = await toggleScanFavorite(id);
      setHistory((prev) =>
        prev.map((item) =>
          item.id === id ? { ...item, isFavorite: updated.isFavorite } : item
        )
      );
    } catch (err) {
      // Roll back the optimistic update on failure.
      setHistory((prev) =>
        prev.map((item) =>
          item.id === id ? { ...item, isFavorite: !item.isFavorite } : item
        )
      );
      setError(err.message || 'Failed to update favorite.');
    }
  };

  /**
   * Delete a single scan on the server, then remove it locally.
   */
  const deleteScan = async (id) => {
    try {
      await deleteScanRequest(id);
      setHistory((prev) => prev.filter((item) => item.id !== id));
    } catch (err) {
      setError(err.message || 'Failed to delete scan.');
    }
  };

  /**
   * Clear the entire scan history on the server and locally.
   */
  const clearHistory = async () => {
    try {
      await clearScansRequest();
      setHistory([]);
    } catch (err) {
      setError(err.message || 'Failed to clear history.');
    }
  };

  return {
    history,
    addScan,
    toggleFavorite,
    deleteScan,
    clearHistory,
    loading,
    error,
    refresh,
  };
};