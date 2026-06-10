import { useState, useEffect } from 'react';
<<<<<<< HEAD
import { Mail, Users, Link, AlertTriangle } from 'lucide-react';
import PageShell from './PageShell';
import { apiFetch } from '../lib/apiBase';

const TEMPLATES = [
  'Password Reset',
  'Invoice',
  'IT Support',
  'HR Notice',
  'Package Delivery',
  'Account Verification',
];
=======
import { Mail, Users, Link, AlertTriangle, Users as UsersIcon } from 'lucide-react';
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'
>>>>>>> origin/main

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

// Fallback campaigns when API is unavailable
const FALLBACK_CAMPAIGNS = [
  { id: 1, name: 'Q4 Awareness Test', type: 'email', active: true, sent: 150, clicked: 23, reported: 12 },
  { id: 2, name: 'Executive Targeting', type: 'smishing', active: false, sent: 45, clicked: 8, reported: 3 },
]

export default function SocialEngineering() {
<<<<<<< HEAD
  const [campaigns, setCampaigns] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchSocialEngineering();
  }, []);

  const fetchSocialEngineering = async () => {
    try {
      const response = await apiFetch('/api/soc/social-engineering');
      if (response.ok) {
        const data = await response.json();
        setCampaigns(data.campaigns || []);
        setStats(data.stats || null);
      }
    } catch (error) {
      console.error('Failed to fetch social engineering data:', error);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return 'text-red-400 bg-red-500/10 border-red-500/30';
      case 'high':
        return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
      case 'medium':
        return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      case 'low':
        return 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30';
      default:
        return 'text-gray-400 bg-gray-500/10 border-gray-500/30';
    }
  };

  const getStatusColor = (status) => {
    switch (status?.toLowerCase()) {
      case 'open':
        return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      case 'closed':
      case 'resolved':
        return 'text-green-400 bg-green-500/10 border-green-500/30';
      default:
        return 'text-gray-400 bg-gray-500/10 border-gray-500/30';
    }
  };

  const statValue = (key) => {
    if (loading) return '…';
    if (stats && stats[key] != null) return stats[key];
    return '—';
  };
=======
  const [campaigns, setCampaigns] = useState([])
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  // Load social engineering campaigns from API
  useEffect(() => {
    const loadData = async () => {
      setLoading(true)
      setError(null)

      try {
        const res = await apiFetch('/api/social-engineering/campaigns')
        if (res.ok) {
          const data = await res.json()
          setCampaigns(Array.isArray(data) ? data : data.campaigns || [])
          setStats(data.stats || null)
        } else if (res.status === 404) {
          // API not implemented, use fallback
          setCampaigns(FALLBACK_CAMPAIGNS)
          const totalSent = FALLBACK_CAMPAIGNS.reduce((a, c) => a + c.sent, 0)
          const totalClicked = FALLBACK_CAMPAIGNS.reduce((a, c) => a + c.clicked, 0)
          const totalReported = FALLBACK_CAMPAIGNS.reduce((a, c) => a + c.reported, 0)
          setStats({
            activeCampaigns: FALLBACK_CAMPAIGNS.filter(c => c.active).length,
            clickRate: totalSent > 0 ? Math.round((totalClicked / totalSent) * 100) : 0,
            reportedCount: totalReported,
            awarenessScore: totalSent > 0 ? Math.round(((totalSent - totalClicked + totalReported) / totalSent) * 100) : 0,
          })
        } else {
          throw new Error(`Failed to load campaigns (HTTP ${res.status})`)
        }
      } catch (err) {
        setError(err?.message || 'Failed to load social engineering data')
        // Use fallback data on error
        setCampaigns(FALLBACK_CAMPAIGNS)
        const totalSent = FALLBACK_CAMPAIGNS.reduce((a, c) => a + c.sent, 0)
        const totalClicked = FALLBACK_CAMPAIGNS.reduce((a, c) => a + c.clicked, 0)
        const totalReported = FALLBACK_CAMPAIGNS.reduce((a, c) => a + c.reported, 0)
        setStats({
          activeCampaigns: FALLBACK_CAMPAIGNS.filter(c => c.active).length,
          clickRate: totalSent > 0 ? Math.round((totalClicked / totalSent) * 100) : 0,
          reportedCount: totalReported,
          awarenessScore: totalSent > 0 ? Math.round(((totalSent - totalClicked + totalReported) / totalSent) * 100) : 0,
        })
      } finally {
        setLoading(false)
      }
    }

    loadData()
  }, [])
>>>>>>> origin/main

  return (
    <PageShell title="Social Engineering Simulator" icon={<UsersIcon />}>
      <div className="space-y-6">
        {/* Error Banner */}
        {error && (
          <div className="rounded-xl border border-amber-500/30 bg-amber-950/20 px-4 py-3">
            <div className="flex items-center gap-2">
              <span className="text-amber-400 text-sm">⚠️</span>
              <span className="text-xs font-mono text-amber-300/80">{error}</span>
              <span className="text-[10px] text-amber-300/50 ml-auto">Using demo data</span>
            </div>
          </div>
        )}

        {/* Loading State */}
        {loading && (
          <div className="flex items-center justify-center py-20">
            <div className="text-center space-y-3">
              <div className="w-8 h-8 border-2 border-purple-500/40 border-t-purple-500 rounded-full animate-spin mx-auto" />
              <p className="text-sm font-mono text-white/40">Loading campaigns...</p>
            </div>
          </div>
        )}

        {/* Campaign Stats */}
<<<<<<< HEAD
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Active Campaigns</span>
              <Mail className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-white">{statValue('active')}</div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Total Campaigns</span>
              <Link className="w-4 h-4 text-yellow-400" />
            </div>
            <div className="text-2xl font-bold text-white">{statValue('total_campaigns')}</div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Critical Findings</span>
              <AlertTriangle className="w-4 h-4 text-red-400" />
            </div>
            <div className="text-2xl font-bold text-white">{statValue('critical_findings')}</div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Assessments Loaded</span>
              <Users className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-2xl font-bold text-white">
              {loading ? '…' : campaigns.length}
            </div>
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

        {/* Campaigns from findings */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
          <div className="p-4 border-b border-white/10">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Mail className="w-4 h-4 text-purple-400" />
              Phishing Assessments
            </h3>
          </div>

          {loading ? (
            <div className="p-8 text-center text-gray-500">
              <div className="animate-spin w-8 h-8 border-2 border-purple-500 border-t-transparent rounded-full mx-auto mb-3" />
              Loading campaigns...
            </div>
          ) : campaigns.length === 0 ? (
            <div className="p-8 text-center text-gray-500">
              No social-engineering findings yet. Run a phishing assessment to populate this view.
            </div>
          ) : (
            <div className="divide-y divide-white/5">
              {campaigns.map((campaign) => (
                <div key={campaign.id} className="p-4 hover:bg-white/5 transition-colors">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-2 flex-wrap">
                        <h4 className="text-sm font-semibold text-white">{campaign.name || 'Untitled'}</h4>
                        {campaign.severity && (
                          <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(campaign.severity)}`}>
                            {campaign.severity}
                          </span>
                        )}
                        {campaign.status && (
                          <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(campaign.status)}`}>
                            {campaign.status}
                          </span>
                        )}
                      </div>
                      {campaign.description && (
                        <p className="text-xs text-gray-400 mb-2 line-clamp-2">{campaign.description}</p>
                      )}
                      <div className="flex items-center gap-3 text-xs text-gray-500">
                        <span>{campaign.type?.replace(/_/g, ' ') || 'phishing assessment'}</span>
                        {campaign.started_at && (
                          <>
                            <span>•</span>
                            <span>{new Date(campaign.started_at).toLocaleDateString()}</span>
                          </>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Templates */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-6">
          <h3 className="text-sm font-semibold text-white mb-4">Phishing Templates</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {TEMPLATES.map((template) => (
              <div
                key={template}
                className="p-4 bg-gradient-to-br from-gray-800/50 to-gray-900/50 border border-white/10 rounded-lg hover:border-purple-500/30 transition-colors cursor-pointer"
              >
                <Mail className="w-5 h-5 text-purple-400 mb-2" />
                <h4 className="text-sm font-medium text-white mb-1">{template}</h4>
                <p className="text-xs text-gray-500">Click to preview</p>
=======
        {!loading && stats && (
          <>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-gray-400">Active Campaigns</span>
                  <Mail className="w-4 h-4 text-cyan-400" />
                </div>
                <div className="text-2xl font-bold text-white">{stats.activeCampaigns}</div>
>>>>>>> origin/main
              </div>

              <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-gray-400">Click Rate</span>
                  <Link className="w-4 h-4 text-yellow-400" />
                </div>
                <div className="text-2xl font-bold text-white">{stats.clickRate}%</div>
              </div>

              <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-gray-400">Reported</span>
                  <AlertTriangle className="w-4 h-4 text-green-400" />
                </div>
                <div className="text-2xl font-bold text-white">{stats.reportedCount}</div>
              </div>

              <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-gray-400">Awareness Score</span>
                  <Users className="w-4 h-4 text-purple-400" />
                </div>
                <div className="text-2xl font-bold text-white">{stats.awarenessScore}%</div>
              </div>
            </div>

            {/* Campaigns List */}
            <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
              <div className="p-4 border-b border-white/10">
                <h3 className="text-sm font-semibold text-white">Active Campaigns</h3>
              </div>

              {campaigns.length === 0 ? (
                <div className="p-12 text-center">
                  <p className="text-sm text-white/40">No campaigns found</p>
                </div>
              ) : (
                <div className="divide-y divide-white/5">
                  {campaigns.map((campaign) => (
                    <div key={campaign.id} className="p-4 hover:bg-white/5 transition-colors">
                      <div className="flex items-center justify-between mb-2">
                        <h4 className="text-sm font-semibold text-white">{campaign.name}</h4>
                        <span className={`px-2 py-1 rounded text-xs font-medium ${
                          campaign.active
                            ? 'bg-green-500/10 text-green-400 border border-green-500/30'
                            : 'bg-gray-500/10 text-gray-400 border border-gray-500/30'
                        }`}>
                          {campaign.active ? 'Active' : 'Completed'}
                        </span>
                      </div>
                      <div className="text-xs text-gray-400 flex gap-4">
                        <span>Type: {campaign.type}</span>
                        <span>Sent: {campaign.sent}</span>
                        <span>Clicked: {campaign.clicked}</span>
                        <span>Reported: {campaign.reported}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </PageShell>
  );
}
