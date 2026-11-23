import { useState, useEffect } from 'react';
import { checkHealth } from '../api/guardianApi';

/**
 * Polls the backend health endpoint and reports a live connection status.
 * Used by the console top bar.
 * @returns {'checking'|'online'|'offline'}
 */
export const useApiStatus = () => {
  const [status, setStatus] = useState('checking');

  useEffect(() => {
    let active = true;

    const verify = async () => {
      const ok = await checkHealth();
      if (active) setStatus(ok ? 'online' : 'offline');
    };

    verify();
    const interval = setInterval(verify, 10000);

    return () => {
      active = false;
      clearInterval(interval);
    };
  }, []);

  return status;
};