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
      const err = await res.json().catch(() => ({ error: 'Request failed' }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    return res.json();
  }, [token, logout]);

  return { apiFetch };
}
