import { useEffect, useRef, useState, useCallback } from 'react';
import { useAuth } from '../context/AuthContext';

export function useWebSocket(path) {
  const { token } = useAuth();
  const wsRef = useRef(null);
  const [lastMessage, setLastMessage] = useState(null);
  const [isConnected, setIsConnected] = useState(false);
  const reconnectTimer = useRef(null);

  const connect = useCallback(() => {
    if (!token) return;
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${proto}//${window.location.host}/sentinel/ws/${path}?token=${token}`;
    const ws = new WebSocket(url);

    ws.onopen = () => setIsConnected(true);
    ws.onmessage = (e) => {
      try {
        setLastMessage(JSON.parse(e.data));
      } catch {
        setLastMessage(e.data);
      }
    };
    ws.onclose = () => {
      setIsConnected(false);
      reconnectTimer.current = setTimeout(connect, 5000);
    };
    ws.onerror = () => ws.close();
    wsRef.current = ws;
  }, [token, path]);

  useEffect(() => {
    connect();
    return () => {
      clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
    };
  }, [connect]);

  return { lastMessage, isConnected };
}
