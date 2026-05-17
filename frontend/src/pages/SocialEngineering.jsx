import { useState } from 'react';
import { Mail, Users, Link, AlertTriangle } from 'lucide-react';
import PageShell from '../components/PageShell';

/**
 * SocialEngineering - Phishing & Social Engineering Simulator
 *
 * Features:
 * - Email phishing campaigns
 * - SMS phishing (smishing)
 * - Voice phishing (vishing)
 * - QR code phishing
 * - Awareness training
 * - User reporting
 */
export default function SocialEngineering() {
  const [campaigns, setCampaigns] = useState([]);

  return (
    <PageShell title="Social Engineering Simulator" icon={<Users />}>
      <div className="space-y-6">
        {/* Campaign Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Active Campaigns</span>
              <Mail className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-white">0</div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Click Rate</span>
              <Link className="w-4 h-4 text-yellow-400" />
            </div>
            <div className="text-2xl font-bold text-white">0%</div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Reported</span>
              <AlertTriangle className="w-4 h-4 text-green-400" />
            </div>
            <div className="text-2xl font-bold text-white">0</div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Awareness Score</span>
              <Users className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-2xl font-bold text-white">--</div>
          </div>
        </div>

        {/* Create Campaign */}
        <div className="bg-gradient-to-r from-purple-500/10 to-pink-500/10 backdrop-blur-md border border-purple-500/30 rounded-xl p-6">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-white mb-1">Create Phishing Campaign</h3>
              <p className="text-xs text-gray-400">
                Test your team's awareness with simulated phishing emails
              </p>
            </div>
            <button className="px-4 py-2 bg-purple-500 text-white rounded-lg text-sm font-medium hover:bg-purple-600 transition-colors">
              New Campaign
            </button>
          </div>
        </div>

        {/* Templates */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-6">
          <h3 className="text-sm font-semibold text-white mb-4">Phishing Templates</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {['Password Reset', 'Invoice', 'IT Support', 'HR Notice', 'Package Delivery', 'Account Verification'].map((template) => (
              <div key={template} className="p-4 bg-gradient-to-br from-gray-800/50 to-gray-900/50 border border-white/10 rounded-lg hover:border-purple-500/30 transition-colors cursor-pointer">
                <Mail className="w-5 h-5 text-purple-400 mb-2" />
                <h4 className="text-sm font-medium text-white mb-1">{template}</h4>
                <p className="text-xs text-gray-500">Click to preview</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </PageShell>
  );
}
