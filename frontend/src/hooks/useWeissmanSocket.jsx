/**
 * frontend/src/hooks/useWeissmanSocket.jsx
 * =========================================
 * Robust WebSocket hook that replaces the raw WebSocket usage in App.jsx.
 *
 * Compatible with:
 *   - Existing backend WebSocket route: /ws/command-center  (server.rs / app.py)
 *   - Redis PubSub events published by src/events_pub.py:
 *       publish_command_center_event(kind, payload)
 *     Event JSON shape: { kind: string, payload: object, ts: number }
 *   - App.jsx: replaces the useEffect WebSocket block; import and call this hook.
 *   - LiveIntelTerminal.jsx: receives `events` array (no other changes needed).
 *   - SecurityScoreGauge.jsx: receives `score` number.
 *   - Globe.jsx: receives `globeData` object.
 *
 * Features added vs original:
 *   1. Auto-reconnect with exponential back-off (1s → 30s cap).
 *   2. Connection status exposed (connecting / online / offline).
 *   3. Empty-state message when no events have arrived yet.
 *   4. Heartbeat ping every 25 s to keep the connection alive through proxies.
 *   5. Cleans up properly on component unmount.
 *
 * Usage in App.jsx:
 *   import { useWeissmanSocket } from './hooks/useWeissmanSocket';
 *
 *   function App() {
 *     const { events, scoreData, globeData, connectionStatus } = useWeissmanSocket();
 *     ...
 *   }
 */

import { useState, useEffect, useRef, useCallback } from 'react';

// ---------------------------------------------------------------------------
// Constants — kept in sync with backend event shapes
// ---------------------------------------------------------------------------
const DEBOUNCE_SAME_EVENT_MS = 5000;
const RECONNECT_BASE_MS = 2000;   // initial reconnect delay
const RECONNECT_MAX_MS = 30000;   // maximum reconnect delay
const HEARTBEAT_INTERVAL_MS = 25000;

// Arc-triggering event kinds (used by App.jsx for visual effects)
const ARC_EVENT_KINDS = new Set([
  'scan_pulse',
  'critical_cve',
  'darkweb',
  'fuzzer_anomaly',
  'new_source_discovered',
  'github_exploit_repo',
  'emergency_alert'
]);

// Build the WebSocket URL from the current page origin so it works behind
// Cloudflare Tunnel and local dev equally.
function buildWsUrl() {
  if (typeof window === 'undefined') return '';
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const host = window.location.host;
  return `${proto}//${host}/ws/command-center`;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------
export function useWeissmanSocket() {
  const [events, setEvents] = useState([]);
  const [scoreData, setScoreData] = useState(null);
  const [globeData, setGlobeData] = useState(null);
  const [connectionStatus, setConnectionStatus] = useState('offline');
  const [emergencyMessage, setEmergencyMessage] = useState('');

  const wsRef = useRef(null);
  const reconnectDelay = useRef(RECONNECT_BASE_MS);
  const reconnectTimer = useRef(null);
  const heartbeatTimer = useRef(null);
  const unmounted = useRef(false);
  const lastTickerKeyRef = useRef({ key: '', t: 0 });
  const eventIdRef = useRef(0);

  // -------------------------------------------------------------------------
  // Message handler — maps backend event kinds to state updates
  // -------------------------------------------------------------------------
  const handleMessage = useCallback((raw) => {
    let data;
    try {
      data = JSON.parse(raw);
    } catch {
      return; // ignore malformed frames
    }

    // --- Initial handshake (sent by server on connect) ---
    if (data.type === 'init' || data.type === 'refresh') {
      if (data.globe) setGlobeData(data.globe);
      if (data.score) setScoreData(data.score);
      setConnectionStatus('online');
      return;
    }

    // --- Process event messages ---
    const kind = data.kind || 'audit';
    const payload = data.payload || {};
    const now = new Date();
    const time = now.toTimeString().slice(0, 8);

    // Determine severity
    let severity = (payload.severity || (kind === 'critical_cve' ? 'high' : 'info')).toLowerCase();

    // Build message based on event kind
    let message;
    if (kind === 'new_source_discovered') {
      message = payload.message || `NEW SOURCE DISCOVERED: ${(payload.url || '').slice(0, 50)}... (${payload.risk_level || 'high'})`;
      severity = (payload.risk_level || 'high').toLowerCase();
    } else if (kind === 'github_exploit_repo') {
      message = payload.message || `Exploit-like repo: ${payload.full_name || '—'}`;
      severity = (payload.severity || 'high').toLowerCase();
    } else if (kind === 'emergency_alert') {
      message = payload.message || 'WARNING: VERIFIED THREAT DETECTED.';
      severity = 'critical';
      setEmergencyMessage(payload.message || message);
    } else if (kind === 'audit') {
      message = (payload.action || '').replace(/_/g, ' ');
    } else {
      message = `[${kind}] ${(payload.message || JSON.stringify(payload)).slice(0, 80)}`;
    }

    // Build target label
    const targetLabel = payload.target || payload.client_name || payload.target_name || payload.url || payload.full_name || '—';

    // Debounce duplicate events
    const key = `${message}|${targetLabel}`;
    const t = Date.now();
    if (lastTickerKeyRef.current.key === key && t - lastTickerKeyRef.current.t < DEBOUNCE_SAME_EVENT_MS) {
      return;
    }
    lastTickerKeyRef.current = { key, t };

    // Create event object
    eventIdRef.current += 1;
    const eventId = `ev-${eventIdRef.current}-${t}`;
    const event = {
      id: eventId,
      time,
      target: targetLabel,
      target_ip: payload.target_ip || payload.target || '—',
      agentId: payload.user_email || payload.agentId || 'Discovery',
      severity,
      message: message || '—',
      kind, // Add kind for arc detection
      payload, // Keep full payload for custom processing
    };

    setEvents((prev) => [...prev, event]);
  }, []);

  // -------------------------------------------------------------------------
  // Connect
  // -------------------------------------------------------------------------
  const connect = useCallback(() => {
    if (unmounted.current) return;

    const url = buildWsUrl();
    if (!url) return;

    setConnectionStatus('offline');

    let ws;
    try {
      ws = new WebSocket(url);
    } catch (err) {
      console.error('[WeissmanSocket] Failed to construct WebSocket:', err);
      scheduleReconnect();
      return;
    }

    wsRef.current = ws;

    ws.onopen = () => {
      if (unmounted.current) {
        ws.close();
        return;
      }
      setConnectionStatus('online');
      reconnectDelay.current = RECONNECT_BASE_MS; // reset back-off on success

      // Start heartbeat pings
      heartbeatTimer.current = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          try {
            ws.send(JSON.stringify({ type: 'ping' }));
          } catch (_) {
            // Ignore ping errors
          }
        }
      }, HEARTBEAT_INTERVAL_MS);
    };

    ws.onmessage = (e) => handleMessage(e.data);

    ws.onerror = (e) => {
      console.warn('[WeissmanSocket] Error:', e);
      setConnectionStatus('offline');
    };

    ws.onclose = (e) => {
      clearInterval(heartbeatTimer.current);
      if (unmounted.current) return;
      setConnectionStatus('offline');
      console.info(
        `[WeissmanSocket] Closed (code=${e.code}). Reconnecting in ${reconnectDelay.current}ms…`
      );
      scheduleReconnect();
    };
  }, [handleMessage]);

  function scheduleReconnect() {
    if (unmounted.current) return;
    if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
    reconnectTimer.current = setTimeout(() => {
      // Exponential back-off capped at RECONNECT_MAX_MS
      reconnectDelay.current = Math.min(
        reconnectDelay.current + 1000,
        RECONNECT_MAX_MS
      );
      connect();
    }, reconnectDelay.current);
  }

  // -------------------------------------------------------------------------
  // Mount / unmount
  // -------------------------------------------------------------------------
  useEffect(() => {
    unmounted.current = false;
    connect();
    return () => {
      unmounted.current = true;
      clearTimeout(reconnectTimer.current);
      clearInterval(heartbeatTimer.current);
      if (wsRef.current) {
        wsRef.current.onclose = null; // prevent reconnect on intentional close
        wsRef.current.close();
      }
      setConnectionStatus('offline');
    };
  }, [connect]);

  return {
    events,
    scoreData,
    globeData,
    connectionStatus,
    emergencyMessage,
    setEmergencyMessage,
    arcEventKinds: ARC_EVENT_KINDS, // Export for App.jsx to use
  };
}

// ---------------------------------------------------------------------------
// ConnectionBadge — optional UI component for status indicator
// Drop into App.jsx header if desired
// ---------------------------------------------------------------------------
export function ConnectionBadge({ status }) {
  const colorMap = {
    connecting: '#fbbf24',
    online: '#10b981',
    offline: '#ef4444',
  };

  const labelMap = {
    connecting: 'CONNECTING',
    online: 'ONLINE',
    offline: 'OFFLINE',
  };

  return (
    <div
      style={{
        display: 'inline-block',
        padding: '4px 12px',
        borderRadius: '4px',
        backgroundColor: 'rgba(0,0,0,0.5)',
        border: `1px solid ${colorMap[status] || '#666'}`,
        color: colorMap[status] || '#666',
        fontSize: '11px',
        fontWeight: '600',
        letterSpacing: '0.5px',
      }}
    >
      <span
        style={{
          display: 'inline-block',
          width: '8px',
          height: '8px',
          borderRadius: '50%',
          backgroundColor: colorMap[status] || '#666',
          marginRight: '6px',
          animation: status === 'online' ? 'pulse 2s infinite' : 'none',
        }}
      />
      {labelMap[status] || status.toUpperCase()}
    </div>
  );
}
