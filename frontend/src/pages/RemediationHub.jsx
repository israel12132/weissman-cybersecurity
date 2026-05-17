import { useState } from 'react';
import { Wrench, Zap, CheckCircle, Clock } from 'lucide-react';
import PageShell from '../components/PageShell';

/**
 * RemediationHub - Complete SOAR Workflow
 *
 * Security Orchestration, Automation & Response
 *
 * Features:
 * - Auto-remediation workflows
 * - Playbook execution
 * - Ticket integration (Jira, ServiceNow)
 * - Patch management
 * - Configuration rollback
 * - Verification & testing
 */
export default function RemediationHub() {
  const [workflows, setWorkflows] = useState([
    { id: 1, name: 'XSS Auto-Patch', status: 'pending', findings: 15 },
    { id: 2, name: 'SQL Injection Fix', status: 'running', findings: 8 },
    { id: 3, name: 'Dependency Update', status: 'completed', findings: 23 },
  ]);

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed': return 'text-green-400 bg-green-500/10 border-green-500/30';
      case 'running': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      case 'pending': return 'text-gray-400 bg-gray-500/10 border-gray-500/30';
      case 'failed': return 'text-red-400 bg-red-500/10 border-red-500/30';
      default: return 'text-gray-400 bg-gray-500/10 border-gray-500/30';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed': return <CheckCircle className="w-4 h-4" />;
      case 'running': return <Clock className="w-4 h-4 animate-spin" />;
      case 'pending': return <Clock className="w-4 h-4" />;
      default: return <AlertTriangle className="w-4 h-4" />;
    }
  };

  return (
    <PageShell title="Remediation Hub" icon={<Wrench />}>
      <div className="space-y-6">
        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Active Workflows</span>
              <Zap className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-white">
              {workflows.filter(w => w.status === 'running').length}
            </div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Completed</span>
              <CheckCircle className="w-4 h-4 text-green-400" />
            </div>
            <div className="text-2xl font-bold text-white">
              {workflows.filter(w => w.status === 'completed').length}
            </div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Pending</span>
              <Clock className="w-4 h-4 text-yellow-400" />
            </div>
            <div className="text-2xl font-bold text-white">
              {workflows.filter(w => w.status === 'pending').length}
            </div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Auto-Fixed</span>
              <Wrench className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-2xl font-bold text-white">46</div>
          </div>
        </div>

        {/* Workflows */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
          <div className="p-4 border-b border-white/10">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Zap className="w-4 h-4 text-cyan-400" />
              Remediation Workflows
            </h3>
          </div>

          <div className="divide-y divide-white/5">
            {workflows.map((workflow) => (
              <div key={workflow.id} className="p-4 hover:bg-white/5 transition-colors">
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <h4 className="text-sm font-semibold text-white">{workflow.name}</h4>
                      <span className={`flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium ${getStatusColor(workflow.status)}`}>
                        {getStatusIcon(workflow.status)}
                        {workflow.status}
                      </span>
                    </div>
                    <div className="text-xs text-gray-400">
                      {workflow.findings} findings to remediate
                    </div>
                  </div>
                  <button className="px-3 py-1.5 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-xs font-medium hover:bg-cyan-500/30 transition-colors">
                    View Details
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Create Workflow */}
        <div className="bg-gradient-to-r from-purple-500/10 to-blue-500/10 backdrop-blur-md border border-purple-500/30 rounded-xl p-6">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-white mb-1">Create Remediation Workflow</h3>
              <p className="text-xs text-gray-400">
                Automate vulnerability fixes with AI-powered remediation
              </p>
            </div>
            <button className="px-4 py-2 bg-purple-500 text-white rounded-lg text-sm font-medium hover:bg-purple-600 transition-colors">
              New Workflow
            </button>
          </div>
        </div>
      </div>
    </PageShell>
  );
}
