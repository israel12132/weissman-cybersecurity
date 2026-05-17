import { useState, useEffect } from 'react';
import { Shield, CheckCircle, XCircle, AlertTriangle, FileText, Download, Filter } from 'lucide-react';
import PageShell from './PageShell';
import { api } from '../utils/apiFetch';

/**
 * ComplianceFrameworks - Multi-framework compliance mapping and tracking
 *
 * Frameworks:
 * - CIS Benchmarks
 * - PCI-DSS
 * - NIST CSF
 * - HIPAA
 * - SOC 2
 * - GDPR
 * - ISO 27001
 * - FedRAMP
 *
 * Features:
 * - Control mapping to findings
 * - Compliance scoring per framework
 * - Gap analysis
 * - Evidence collection
 * - Audit report generation
 */
export default function ComplianceFrameworks() {
  const [frameworks, setFrameworks] = useState([]);
  const [selectedFramework, setSelectedFramework] = useState(null);
  const [controls, setControls] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all'); // all, compliant, non-compliant, partial

  const frameworksList = [
    { id: 'cis', name: 'CIS Benchmarks', icon: '🛡️' },
    { id: 'pci-dss', name: 'PCI-DSS', icon: '💳' },
    { id: 'nist', name: 'NIST CSF', icon: '🏛️' },
    { id: 'hipaa', name: 'HIPAA', icon: '🏥' },
    { id: 'soc2', name: 'SOC 2', icon: '📊' },
    { id: 'gdpr', name: 'GDPR', icon: '🇪🇺' },
    { id: 'iso27001', name: 'ISO 27001', icon: '🔐' },
    { id: 'fedramp', name: 'FedRAMP', icon: '🇺🇸' },
  ];

  useEffect(() => {
    fetchFrameworks();
  }, []);

  useEffect(() => {
    if (selectedFramework) {
      fetchControls(selectedFramework.id);
    }
  }, [selectedFramework]);

  const fetchFrameworks = async () => {
    try {
      setLoading(true);
      const data = await api.get('/api/compliance/frameworks');
      setFrameworks(data.frameworks || []);
      if (data.frameworks.length > 0) {
        setSelectedFramework(data.frameworks[0]);
      }
    } catch (error) {
      console.error('Failed to fetch frameworks:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchControls = async (frameworkId) => {
    try {
      const data = await api.get(`/api/compliance/frameworks/${frameworkId}/controls`);
      setControls(data.controls || []);
    } catch (error) {
      console.error('Failed to fetch controls:', error);
    }
  };

  const generateReport = async (frameworkId) => {
    try {
      const blob = await api.get(`/api/compliance/frameworks/${frameworkId}/report`, {
        responseType: 'blob',
      });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `${frameworkId}-compliance-report.pdf`;
      link.click();
    } catch (error) {
      console.error('Failed to generate report:', error);
    }
  };

  const getComplianceColor = (status) => {
    switch (status?.toLowerCase()) {
      case 'compliant':
        return 'text-green-400 bg-green-500/10 border-green-500/30';
      case 'non-compliant':
        return 'text-red-400 bg-red-500/10 border-red-500/30';
      case 'partial':
        return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      default:
        return 'text-gray-400 bg-gray-500/10 border-gray-500/30';
    }
  };

  const getComplianceIcon = (status) => {
    switch (status?.toLowerCase()) {
      case 'compliant':
        return <CheckCircle className="w-4 h-4" />;
      case 'non-compliant':
        return <XCircle className="w-4 h-4" />;
      case 'partial':
        return <AlertTriangle className="w-4 h-4" />;
      default:
        return <AlertTriangle className="w-4 h-4" />;
    }
  };

  const filteredControls = controls.filter((c) => {
    if (filter === 'all') return true;
    return c.status === filter;
  });

  const stats = selectedFramework
    ? {
        total: controls.length,
        compliant: controls.filter((c) => c.status === 'compliant').length,
        nonCompliant: controls.filter((c) => c.status === 'non-compliant').length,
        partial: controls.filter((c) => c.status === 'partial').length,
        score: controls.length > 0
          ? ((controls.filter((c) => c.status === 'compliant').length / controls.length) * 100).toFixed(1)
          : 0,
      }
    : { total: 0, compliant: 0, nonCompliant: 0, partial: 0, score: 0 };

  return (
    <PageShell title="Compliance Frameworks" icon={<Shield />}>
      <div className="space-y-6">
        {/* Framework Selector */}
        <div className="flex items-center gap-3 overflow-x-auto pb-2">
          {frameworksList.map((fw) => {
            const frameworkData = frameworks.find((f) => f.id === fw.id);
            const isSelected = selectedFramework?.id === fw.id;

            return (
              <button
                key={fw.id}
                onClick={() => setSelectedFramework(frameworkData || fw)}
                className={`flex items-center gap-2 px-4 py-3 rounded-xl border transition-all whitespace-nowrap ${
                  isSelected
                    ? 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30'
                    : 'bg-black/40 text-gray-400 border-white/10 hover:bg-white/5 hover:text-white'
                }`}
              >
                <span className="text-xl">{fw.icon}</span>
                <div className="text-left">
                  <div className="text-sm font-semibold">{fw.name}</div>
                  {frameworkData && (
                    <div className="text-xs opacity-75">{frameworkData.score}% compliant</div>
                  )}
                </div>
              </button>
            );
          })}
        </div>

        {/* Stats */}
        {selectedFramework && (
          <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
            <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-gray-400">Total Controls</span>
                <FileText className="w-4 h-4 text-cyan-400" />
              </div>
              <div className="text-2xl font-bold text-white">{stats.total}</div>
            </div>

            <div className="bg-green-500/10 backdrop-blur-md border border-green-500/30 rounded-xl p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-green-400">Compliant</span>
                <CheckCircle className="w-4 h-4 text-green-400" />
              </div>
              <div className="text-2xl font-bold text-green-400">{stats.compliant}</div>
            </div>

            <div className="bg-red-500/10 backdrop-blur-md border border-red-500/30 rounded-xl p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-red-400">Non-Compliant</span>
                <XCircle className="w-4 h-4 text-red-400" />
              </div>
              <div className="text-2xl font-bold text-red-400">{stats.nonCompliant}</div>
            </div>

            <div className="bg-yellow-500/10 backdrop-blur-md border border-yellow-500/30 rounded-xl p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-yellow-400">Partial</span>
                <AlertTriangle className="w-4 h-4 text-yellow-400" />
              </div>
              <div className="text-2xl font-bold text-yellow-400">{stats.partial}</div>
            </div>

            <div className="bg-cyan-500/10 backdrop-blur-md border border-cyan-500/30 rounded-xl p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-cyan-400">Score</span>
                <Shield className="w-4 h-4 text-cyan-400" />
              </div>
              <div className="text-2xl font-bold text-cyan-400">{stats.score}%</div>
            </div>
          </div>
        )}

        {/* Controls and Filters */}
        {selectedFramework && (
          <>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 bg-black/40 backdrop-blur-md border border-white/10 rounded-lg p-1">
                {['all', 'compliant', 'non-compliant', 'partial'].map((f) => (
                  <button
                    key={f}
                    onClick={() => setFilter(f)}
                    className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                      filter === f
                        ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                        : 'text-gray-400 hover:text-white hover:bg-white/5'
                    }`}
                  >
                    {f.charAt(0).toUpperCase() + f.slice(1).replace('-', ' ')}
                  </button>
                ))}
              </div>

              <button
                onClick={() => generateReport(selectedFramework.id)}
                className="flex items-center gap-2 px-4 py-2 bg-cyan-500 text-white rounded-lg font-medium hover:bg-cyan-600 transition-colors"
              >
                <Download className="w-4 h-4" />
                Generate Report
              </button>
            </div>

            {/* Controls List */}
            <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
              <div className="p-4 border-b border-white/10">
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <FileText className="w-4 h-4 text-cyan-400" />
                  {selectedFramework.name} Controls ({filteredControls.length})
                </h3>
              </div>

              {loading ? (
                <div className="p-8 text-center text-gray-500">
                  <div className="animate-spin w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full mx-auto mb-3" />
                  Loading controls...
                </div>
              ) : filteredControls.length === 0 ? (
                <div className="p-8 text-center text-gray-500">
                  No controls found for this filter.
                </div>
              ) : (
                <div className="divide-y divide-white/5 max-h-[600px] overflow-y-auto">
                  {filteredControls.map((control) => (
                    <div
                      key={control.id}
                      className="p-4 hover:bg-white/5 transition-colors"
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-3 mb-2">
                            <span className="text-xs font-mono text-gray-500 bg-white/5 px-2 py-1 rounded">
                              {control.control_id}
                            </span>
                            <h4 className="text-sm font-semibold text-white">
                              {control.title}
                            </h4>
                            <span
                              className={`flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium ${getComplianceColor(
                                control.status
                              )}`}
                            >
                              {getComplianceIcon(control.status)}
                              {control.status}
                            </span>
                          </div>

                          <p className="text-xs text-gray-400 mb-3">
                            {control.description}
                          </p>

                          {/* Mapped Findings */}
                          {control.findings && control.findings.length > 0 && (
                            <div className="mt-2">
                              <span className="text-xs text-gray-500">
                                Mapped findings: {control.findings.length}
                              </span>
                              <div className="flex gap-2 mt-1">
                                {control.findings.slice(0, 3).map((finding) => (
                                  <span
                                    key={finding.id}
                                    className="text-xs px-2 py-1 bg-red-500/10 text-red-400 border border-red-500/20 rounded"
                                  >
                                    {finding.title}
                                  </span>
                                ))}
                                {control.findings.length > 3 && (
                                  <span className="text-xs px-2 py-1 bg-white/5 text-gray-400 rounded">
                                    +{control.findings.length - 3} more
                                  </span>
                                )}
                              </div>
                            </div>
                          )}

                          {/* Evidence */}
                          {control.evidence && (
                            <div className="mt-2 flex items-center gap-2 text-xs text-gray-500">
                              <FileText className="w-3 h-3" />
                              {control.evidence.count} evidence files attached
                            </div>
                          )}
                        </div>

                        <button className="px-3 py-1.5 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-xs font-medium hover:bg-cyan-500/30 transition-colors">
                          View Details
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </>
        )}

        {/* Gap Analysis */}
        {selectedFramework && stats.nonCompliant > 0 && (
          <div className="bg-red-500/10 backdrop-blur-md border border-red-500/30 rounded-xl p-6">
            <div className="flex items-center gap-2 mb-4">
              <AlertTriangle className="w-5 h-5 text-red-400" />
              <h3 className="text-sm font-semibold text-white">Gap Analysis</h3>
            </div>
            <p className="text-sm text-gray-300 mb-4">
              {stats.nonCompliant} controls are non-compliant. Addressing these gaps is critical for
              achieving {selectedFramework.name} certification.
            </p>
            <button className="px-4 py-2 bg-red-500 text-white rounded-lg text-sm font-medium hover:bg-red-600 transition-colors">
              View Remediation Plan
            </button>
          </div>
        )}
      </div>
    </PageShell>
  );
}
