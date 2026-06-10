import { useState, useEffect, useMemo, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { Network, Globe, Shield, Activity, AlertTriangle } from 'lucide-react';
import PageShell from './PageShell';
import { apiFetch } from '../lib/apiBase';

/**
 * NetworkProtocols — probe-derived protocol exposure from live findings and,
 * when a client is selected, contextual risk-graph network nodes. No fabricated stats.
 */

const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

const NETWORK_SOURCES = new Set([
  'asm',
  'bgp_dns_hijacking',
  'ipv6_attack',
  'mtls_grpc',
  'smb_netbios',
  'pki_tls',
  'discovery_engine',
  'recon',
]);

const ENGINE_PROTOCOL_NAMES = {
  bgp_dns_hijacking: 'DNS / BGP',
  ipv6_attack: 'IPv6',
  mtls_grpc: 'mTLS / gRPC',
  smb_netbios: 'SMB / NetBIOS',
  pki_tls: 'TLS / SSL',
  asm: 'ASM Services',
};

function parseFindingsResponse(data) {
  return Array.isArray(data) ? data : Array.isArray(data?.findings) ? data.findings : [];
}

function findingSource(f) {
  return (f.source || f.engine || '').toLowerCase();
}

function isNetworkFinding(f) {
  const src = findingSource(f);
  if (NETWORK_SOURCES.has(src)) return true;
  const text = `${f.title || ''} ${f.description || ''}`.toLowerCase();
  return /smb|netbios|dns|bgp|tls|ssl|ftp|smtp|ssh|grpc|mtls|ipv6|open port|exposed.+port|port.?(\d{2,5})/i.test(text);
}

function classifyProtocol(finding) {
  const src = findingSource(finding);
  if (ENGINE_PROTOCOL_NAMES[src]) return ENGINE_PROTOCOL_NAMES[src];

  const text = `${finding.title || ''} ${finding.description || ''}`.toLowerCase();
  if (/smb|netbios|port.?445|port.?139|port.?137/.test(text)) return 'SMB';
  if (/\bftp\b/.test(text)) return 'FTP';
  if (/\bsmtp\b/.test(text)) return 'SMTP';
  if (/\bssh\b/.test(text)) return 'SSH';
  if (/\bdns\b|bgp\b|hijack/.test(text)) return 'DNS';
  if (/tls|ssl|hsts|certificate/.test(text)) return 'TLS/SSL';
  if (/grpc|mtls/.test(text)) return 'mTLS / gRPC';
  if (/ipv6|aaaa/.test(text)) return 'IPv6';
  if (/http/.test(text)) return 'HTTP/HTTPS';
  if (src === 'asm') return 'ASM Services';
  return null;
}

function statusFromSeverities(severities, count) {
  const max = severities.reduce((m, s) => Math.max(m, SEVERITY_ORDER[s] ?? 0), 0);
  if (max >= SEVERITY_ORDER.critical || max >= SEVERITY_ORDER.high) return 'critical';
  if (max >= SEVERITY_ORDER.medium || count > 3) return 'warning';
  if (count > 0) return 'warning';
  return 'secure';
}

function protocolsFromFindings(findings) {
  const buckets = new Map();
  for (const f of findings) {
    if (!isNetworkFinding(f)) continue;
    const name = classifyProtocol(f);
    if (!name) continue;
    const cur = buckets.get(name) || { name, findings: 0, severities: [] };
    cur.findings += 1;
    cur.severities.push((f.severity || 'info').toLowerCase());
    buckets.set(name, cur);
  }
  return Array.from(buckets.values()).map((p) => ({
    name: p.name,
    findings: p.findings,
    status: statusFromSeverities(p.severities, p.findings),
  }));
}

function protocolNameFromRiskNode(node) {
  const ext = node.external_id || '';
  if (ext.startsWith('ot:')) {
    const parts = ext.split(':');
    if (parts.length >= 4 && parts[3]) return parts[3].toUpperCase();
  }
  const label = (node.label || '').trim();
  if (!label) return 'Network';
  const first = label.split(/\s+/)[0];
  return first.length <= 12 ? first : label.slice(0, 40);
}

function protocolsFromRiskGraph(nodes) {
  const buckets = new Map();
  for (const n of nodes) {
    const nt = (n.node_type || '').toLowerCase();
    if (nt !== 'network' && nt !== 'physical_asset') continue;
    const name = protocolNameFromRiskNode(n);
    const cur = buckets.get(name) || { name, findings: 0, severities: [] };
    cur.findings += 1;
    const score = Number(n.risk_score) || 0;
    if (score >= 8) cur.severities.push('critical');
    else if (score >= 5) cur.severities.push('high');
    else cur.severities.push('medium');
    buckets.set(name, cur);
  }
  return Array.from(buckets.values()).map((p) => ({
    name: p.name,
    findings: p.findings,
    status: statusFromSeverities(p.severities, p.findings),
  }));
}

function mergeProtocols(primary, supplemental) {
  const map = new Map(primary.map((p) => [p.name, { ...p }]));
  for (const p of supplemental) {
    const existing = map.get(p.name);
    if (existing) {
      existing.findings += p.findings;
      const mergedStatus = [existing.status, p.status];
      existing.status = mergedStatus.includes('critical')
        ? 'critical'
        : mergedStatus.includes('warning')
          ? 'warning'
          : 'secure';
    } else {
      map.set(p.name, { ...p });
    }
  }
  return Array.from(map.values()).sort((a, b) => b.findings - a.findings);
}

function getStatusColor(status) {
  switch (status) {
    case 'critical': return 'text-red-400 bg-red-500/10 border-red-500/30';
    case 'warning': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
    case 'secure': return 'text-green-400 bg-green-500/10 border-green-500/30';
    default: return 'text-gray-400 bg-gray-500/10 border-gray-500/30';
  }
}

export default function NetworkProtocols() {
  const [clients, setClients] = useState([]);
  const [selectedClientId, setSelectedClientId] = useState('');
  const [protocols, setProtocols] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [dataSource, setDataSource] = useState('findings');

  useEffect(() => {
    apiFetch('/api/clients')
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => { if (Array.isArray(d)) setClients(d); })
      .catch(() => {});
  }, []);

  const loadProtocols = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await apiFetch('/api/soc/network-protocols');
      if (!response.ok) throw new Error(`SOC HTTP ${response.status}`);
      const data = await response.json();
      const list = Array.isArray(data?.protocols) ? data.protocols : [];
      setProtocols(list);
      setDataSource('soc');
    } catch (e) {
      setProtocols([]);
      setError(e.message || 'Failed to load protocol data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadProtocols().catch(() => {});
  }, [loadProtocols]);

  const stats = useMemo(() => ({
    scanned: protocols.length,
    critical: protocols.filter((p) => p.status === 'critical').length,
    warning: protocols.filter((p) => p.status === 'warning').length,
    secure: protocols.filter((p) => p.status === 'secure').length,
  }), [protocols]);

  return (
    <PageShell title="Network Protocol Analysis" icon={<Network />}>
      <div className="space-y-6">
        <div className="flex flex-wrap items-center gap-3">
          <span className="text-[11px] font-mono text-white/40">Client scope:</span>
          <select
            value={selectedClientId}
            onChange={(e) => setSelectedClientId(e.target.value)}
            className="bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 text-xs text-white/80 font-mono focus:outline-none focus:border-cyan-500/40"
          >
            <option value="">All clients (tenant findings)</option>
            {clients.map((c) => (
              <option key={c.id} value={c.id}>{c.name}</option>
            ))}
          </select>
          <span className="text-[10px] font-mono text-white/30">
            Source: {dataSource === 'soc' ? '/api/soc/network-protocols' : dataSource}
          </span>
          <Link to="/findings" className="text-xs text-cyan-300 hover:text-cyan-200 ml-auto">Open Findings C2 →</Link>
        </div>

        {error && (
          <div className="p-4 rounded-xl border border-red-500/30 bg-red-900/20 text-red-300 text-sm">
            Could not load protocol data: {error}.
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Protocols Scanned</span>
              <Network className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-white">{loading ? '…' : stats.scanned}</div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Critical Issues</span>
              <AlertTriangle className="w-4 h-4 text-red-400" />
            </div>
            <div className="text-2xl font-bold text-white">{loading ? '…' : stats.critical}</div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Warnings</span>
              <Activity className="w-4 h-4 text-yellow-400" />
            </div>
            <div className="text-2xl font-bold text-white">{loading ? '…' : stats.warning}</div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Secure</span>
              <Shield className="w-4 h-4 text-green-400" />
            </div>
            <div className="text-2xl font-bold text-white">{loading ? '…' : stats.secure}</div>
          </div>
        </div>

        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
          <div className="p-4 border-b border-white/10">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyan-400" />
              Network Protocols
            </h3>
          </div>

          {loading ? (
            <div className="p-6 text-sm text-white/40">Loading probe-derived protocol data…</div>
          ) : protocols.length === 0 ? (
            <div className="p-6 space-y-3 text-sm text-white/50">
              <p>No network protocol findings yet.</p>
              <p className="text-xs text-white/35">
                Run ASM or network engines (BGP/DNS, IPv6, mTLS/gRPC, SMB/NetBIOS, PKI/TLS) from{' '}
                <Link to="/network" className="text-cyan-300 hover:text-cyan-200">Network Intelligence</Link>
                {' '}or the engine room. Select a client to merge risk-graph network nodes when available.
              </p>
            </div>
          ) : (
            <div className="divide-y divide-white/5">
              {protocols.map((protocol) => (
                <div key={protocol.name} className="p-4 hover:bg-white/5 transition-colors">
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <h4 className="text-sm font-semibold text-white">{protocol.name}</h4>
                        <span className={`px-2 py-1 rounded text-xs font-medium border ${getStatusColor(protocol.status)}`}>
                          {protocol.status}
                        </span>
                      </div>
                      <div className="text-xs text-gray-400">
                        {protocol.findings} {protocol.findings === 1 ? 'finding' : 'findings'} from live probes
                      </div>
                    </div>
                    <Link
                      to="/findings"
                      className="px-3 py-1.5 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-xs font-medium hover:bg-cyan-500/30 transition-colors"
                    >
                      View findings
                    </Link>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </PageShell>
  );
}
