import { useCallback } from 'react';
import { useAuth } from '../context/AuthContext';

export function useAPI() {
  const { token, logout } = useAuth();

  const apiFetch = useCallback(async (path, options = {}) => {
    const res = await fetch(`/sentinel/api${path}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...options.headers,
      },
    });
    if (res.status === 401) {
      logout();
      throw new Error('Session expired');
    }
    if (!res.ok) {
      const body = await res.json().catch(() => ({ error: 'Request failed' }));
      const err = new Error(body.error || `HTTP ${res.status}`);
      // Callers that need to branch on a specific failure (e.g. the 409
      // EPHEMERAL_STORAGE refusal on the Reports page) read these.
      err.status = res.status;
      err.code = body.code;
      throw err;
    }
    return res.json();
  }, [token, logout]);

  return { apiFetch };
}
