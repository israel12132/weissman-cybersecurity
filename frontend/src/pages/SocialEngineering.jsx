import { useState, useEffect } from 'react';
import { Mail, Users, Link, AlertTriangle, Users as UsersIcon } from 'lucide-react';
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'

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
        {!loading && stats && (
          <>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-gray-400">Active Campaigns</span>
                  <Mail className="w-4 h-4 text-cyan-400" />
                </div>
                <div className="text-2xl font-bold text-white">{stats.activeCampaigns}</div>
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
