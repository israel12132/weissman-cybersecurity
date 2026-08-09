/**
 * frontend/src/hooks/useWeissmanSocket.jsx
 * =========================================
 * Robust WebSocket hook that replaces the raw WebSocket usage in App.jsx.
 *
 * Compatible with:
 *   - Rust backend WebSocket: GET /ws/command-center (weissman-server / fingerprint_engine::http)
 *   - Redis telemetry bus when REDIS_URL is set (cross-replica fan-out)
 *   - Event JSON shape: { kind: string, payload: object, ts: number }
 *   - App.jsx: replaces the useEffect WebSocket block; import and call this hook.
 *   - LiveIntelTerminal.jsx: receives `events` array (no other changes needed).
 *   - SecurityScoreGauge.jsx: receives `score` number.
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
 *     const { events, scoreData, connectionStatus } = useWeissmanSocket();
 *     ...
 *   }
 */

import { useState, useEffect, useRef, useCallback } from 'react';
import { getApiBase } from '../lib/apiBase';

// ---------------------------------------------------------------------------
// Constants — kept in sync with backend event shapes
// ---------------------------------------------------------------------------
const DEBOUNCE_SAME_EVENT_MS = 5000;
const RECONNECT_BASE_MS = 1000;   // initial reconnect delay (doubles per attempt → 30s cap)
const RECONNECT_MAX_MS = 30000;   // maximum reconnect delay
const MAX_EVENTS = 500;           // cap the live buffer so a long shift on a
                                  // busy feed can't grow the array unbounded
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

// Build the WebSocket URL from the configured API origin (getApiBase) so it tracks
// the same host as every HTTP call — including a build that sets VITE_API_BASE_URL,
// where deriving from window.location would dial the static-asset origin instead of
// the API. Falls back to the page origin for same-origin prod and the dev proxy.
// On reconnect we pass the last event sequence we saw so the server can replay
// everything we missed while offline.
function buildWsUrl(lastEventId) {
  if (typeof window === 'undefined') return '';
  const origin = getApiBase() || window.location.origin;
  const base = `${origin.replace(/^http/, 'ws')}/ws/command-center`;
  return lastEventId > 0 ? `${base}?last_event_id=${lastEventId}` : base;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------
export function useWeissmanSocket() {
  const [events, setEvents] = useState([]);
  const [scoreData, setScoreData] = useState(null);
  const [connectionStatus, setConnectionStatus] = useState('offline');
  const [emergencyMessage, setEmergencyMessage] = useState('');
  // Bumped every time the server reports it dropped events for this (slow) client.
  // Consumers watch this (e.g. useEffect([resyncSignal]) → refetch) to recover the
  // events they missed instead of trusting a live feed that now has a gap in it.
  const [resyncSignal, setResyncSignal] = useState(0);

  const wsRef = useRef(null);
  const reconnectDelay = useRef(RECONNECT_BASE_MS);
  const reconnectTimer = useRef(null);
  const heartbeatTimer = useRef(null);
  const unmounted = useRef(false);
  const lastTickerKeyRef = useRef({ key: '', t: 0 });
  const eventIdRef = useRef(0);
  // Highest server sequence (`_seq`) we've received. Sent as last_event_id on reconnect
  // so the server replays the events we missed while the socket was down.
  const lastEventIdRef = useRef(0);

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

    // Track the server sequence so a reconnect can resume via last_event_id.
    if (typeof data._seq === 'number' && data._seq > lastEventIdRef.current) {
      lastEventIdRef.current = data._seq;
    }

    // --- Initial handshake (sent by server on connect) ---
    if (data.type === 'init' || data.type === 'refresh') {
      if (data.score) setScoreData(data.score);
      setConnectionStatus('online');
      return;
    }

    // --- Resync signal: the server dropped events for this slow client (broadcast
    //     backpressure). The live feed now has a gap, so bump resyncSignal and let
    //     consumers refetch authoritative state rather than silently miss events. ---
    if (data.type === 'resync' || data.kind === 'stream_lagged') {
      setResyncSignal((n) => n + 1);
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

    setEvents((prev) => {
      const next = [...prev, event];
      return next.length > MAX_EVENTS ? next.slice(-MAX_EVENTS) : next;
    });
  }, []);

  // -------------------------------------------------------------------------
  // Connect
  // -------------------------------------------------------------------------
  const connect = useCallback(() => {
    if (unmounted.current) return;

    const url = buildWsUrl(lastEventIdRef.current);
    if (!url) return;

    // We are actively opening a socket — surface the amber CONNECTING state that
    // ConnectionBadge renders, not OFFLINE (which is reserved for a dropped feed).
    setConnectionStatus('connecting');

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
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [handleMessage]);

  function scheduleReconnect() {
    if (unmounted.current) return;
    if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
    reconnectTimer.current = setTimeout(() => {
      // Exponential back-off (double each attempt) capped at RECONNECT_MAX_MS, to
      // match the documented 1s → 30s contract. Additive growth took ~29 attempts
      // to reach the cap, hammering an already-unhealthy backend.
      reconnectDelay.current = Math.min(
        reconnectDelay.current * 2,
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
    connectionStatus,
    emergencyMessage,
    setEmergencyMessage,
    resyncSignal, // bumps when the server dropped events; consumers refetch on change
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
