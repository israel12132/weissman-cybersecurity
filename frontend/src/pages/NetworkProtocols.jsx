import { useState } from 'react';
import { Network, Globe, Shield, Activity } from 'lucide-react';
import PageShell from '../components/PageShell';

/**
 * NetworkProtocols - Deep Network Protocol Analysis
 *
 * Covers:
 * - BGP/DNS Hijacking detection
 * - IPv6 attack vectors
 * - mTLS/gRPC security
 * - SMB/NetBIOS exposure
 * - TCP/UDP protocol fuzzing
 * - TLS/SSL misconfiguration
 */
export default function NetworkProtocols() {
  const [protocols, setProtocols] = useState([
    { name: 'HTTP/HTTPS', status: 'secure', findings: 2 },
    { name: 'DNS', status: 'warning', findings: 5 },
    { name: 'SMB', status: 'critical', findings: 12 },
    { name: 'SSH', status: 'secure', findings: 0 },
    { name: 'FTP', status: 'critical', findings: 8 },
    { name: 'SMTP', status: 'warning', findings: 3 },
  ]);

  const getStatusColor = (status) => {
    switch (status) {
      case 'critical': return 'text-red-400 bg-red-500/10 border-red-500/30';
      case 'warning': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      case 'secure': return 'text-green-400 bg-green-500/10 border-green-500/30';
      default: return 'text-gray-400 bg-gray-500/10 border-gray-500/30';
    }
  };

  return (
    <PageShell title="Network Protocol Analysis" icon={<Network />}>
      <div className="space-y-6">
        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Protocols Scanned</span>
              <Network className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-white">{protocols.length}</div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Critical Issues</span>
              <AlertTriangle className="w-4 h-4 text-red-400" />
            </div>
            <div className="text-2xl font-bold text-white">
              {protocols.filter(p => p.status === 'critical').length}
            </div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Warnings</span>
              <Activity className="w-4 h-4 text-yellow-400" />
            </div>
            <div className="text-2xl font-bold text-white">
              {protocols.filter(p => p.status === 'warning').length}
            </div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Secure</span>
              <Shield className="w-4 h-4 text-green-400" />
            </div>
            <div className="text-2xl font-bold text-white">
              {protocols.filter(p => p.status === 'secure').length}
            </div>
          </div>
        </div>

        {/* Protocol List */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
          <div className="p-4 border-b border-white/10">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyan-400" />
              Network Protocols
            </h3>
          </div>

          <div className="divide-y divide-white/5">
            {protocols.map((protocol) => (
              <div key={protocol.name} className="p-4 hover:bg-white/5 transition-colors">
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <h4 className="text-sm font-semibold text-white">{protocol.name}</h4>
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(protocol.status)}`}>
                        {protocol.status}
                      </span>
                    </div>
                    <div className="text-xs text-gray-400">
                      {protocol.findings} findings discovered
                    </div>
                  </div>
                  <button className="px-3 py-1.5 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-xs font-medium hover:bg-cyan-500/30 transition-colors">
                    Analyze
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </PageShell>
  );
}
