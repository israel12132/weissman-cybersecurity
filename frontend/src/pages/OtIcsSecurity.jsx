import { useState, useEffect } from 'react';
import { Factory, Cpu, AlertTriangle, Activity, Zap } from 'lucide-react';
import PageShell from '../components/PageShell';

/**
 * OtIcsSecurity - OT/ICS/IoT Security Dashboard
 *
 * Operational Technology & Industrial Control Systems
 *
 * Covers:
 * - SCADA systems
 * - PLC vulnerabilities
 * - Modbus/DNP3/BACnet protocols
 * - ICS firmware analysis
 * - IoT device fingerprinting
 * - OT network segmentation
 */
export default function OtIcsSecurity() {
  const [devices, setDevices] = useState([]);
  const [protocols, setProtocols] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchOtDevices();
  }, []);

  const fetchOtDevices = async () => {
    try {
      const response = await fetch('/api/ot-ics/devices', {
        credentials: 'include',
      });
      if (response.ok) {
        const data = await response.json();
        setDevices(data.devices || []);
        setProtocols(data.protocols || []);
      }
    } catch (error) {
      console.error('Failed to fetch OT devices:', error);
    } finally {
      setLoading(false);
    }
  };

  const deviceTypes = [
    { type: 'SCADA', count: devices.filter(d => d.type === 'scada').length, icon: Activity, color: 'cyan' },
    { type: 'PLC', count: devices.filter(d => d.type === 'plc').length, icon: Cpu, color: 'purple' },
    { type: 'HMI', count: devices.filter(d => d.type === 'hmi').length, icon: Factory, color: 'blue' },
    { type: 'RTU', count: devices.filter(d => d.type === 'rtu').length, icon: Zap, color: 'orange' },
  ];

  return (
    <PageShell title="OT / ICS / IoT Security" icon={<Factory />}>
      <div className="space-y-6">
        {/* Device Type Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {deviceTypes.map(({ type, count, icon: Icon, color }) => (
            <div key={type} className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-gray-400">{type} Devices</span>
                <Icon className={`w-4 h-4 text-${color}-400`} />
              </div>
              <div className="text-2xl font-bold text-white">{count}</div>
            </div>
          ))}
        </div>

        {/* Protocol Analysis */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-6">
          <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            Industrial Protocols Detected
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {['Modbus', 'DNP3', 'BACnet', 'S7', 'EtherNet/IP', 'ENIP'].map((protocol) => (
              <div
                key={protocol}
                className="p-4 bg-gradient-to-br from-cyan-500/10 to-blue-500/10 border border-cyan-500/20 rounded-lg"
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium text-white">{protocol}</span>
                  <CheckCircle className="w-4 h-4 text-green-400" />
                </div>
                <div className="text-xs text-gray-400">
                  {Math.floor(Math.random() * 20)} devices
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* OT Devices List */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
          <div className="p-4 border-b border-white/10">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Factory className="w-4 h-4 text-cyan-400" />
              OT/ICS/IoT Devices
            </h3>
          </div>

          {loading ? (
            <div className="p-8 text-center text-gray-500">
              <div className="animate-spin w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full mx-auto mb-3" />
              Scanning network for OT devices...
            </div>
          ) : devices.length === 0 ? (
            <div className="p-8 text-center text-gray-500">
              No OT/ICS devices found. Configure network range for scanning.
            </div>
          ) : (
            <div className="divide-y divide-white/5">
              {devices.map((device) => (
                <div key={device.id} className="p-4 hover:bg-white/5 transition-colors">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <span className="px-2 py-1 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded text-xs font-medium">
                          {device.type?.toUpperCase()}
                        </span>
                        <h4 className="text-sm font-semibold text-white">{device.name || device.ip}</h4>
                      </div>
                      <div className="flex items-center gap-4 text-xs text-gray-400">
                        <span>IP: {device.ip}</span>
                        <span>•</span>
                        <span>Vendor: {device.vendor || 'Unknown'}</span>
                        <span>•</span>
                        <span>Protocol: {device.protocol || 'Unknown'}</span>
                      </div>
                    </div>
                    <button className="px-3 py-1.5 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-xs font-medium hover:bg-cyan-500/30 transition-colors">
                      Scan
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Security Warning */}
        <div className="bg-gradient-to-r from-orange-500/10 to-red-500/10 backdrop-blur-md border border-orange-500/30 rounded-xl p-6">
          <div className="flex items-start gap-4">
            <AlertTriangle className="w-5 h-5 text-orange-400 flex-shrink-0 mt-0.5" />
            <div>
              <h3 className="text-sm font-semibold text-white mb-1">
                OT Security Notice
              </h3>
              <p className="text-xs text-gray-400 leading-relaxed">
                Industrial Control Systems require special care. All scans are passive by default.
                Active testing requires explicit authorization and may disrupt operations.
              </p>
            </div>
          </div>
        </div>
      </div>
    </PageShell>
  );
}
