import { useEffect, useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'

export default function ClientDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [client, setClient] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [launchingScan, setLaunchingScan] = useState(false)
  const [scanResult, setScanResult] = useState(null)

  useEffect(() => {
    loadClient()
  }, [id])

  async function loadClient() {
    setLoading(true)
    setError('')
    try {
      // Try to get client details - the API may return client data directly or in a response wrapper
      const response = await apiFetch(`/api/clients/${id}`)
      if (!response.ok) {
        if (response.status === 404) {
          setError('Client not found')
        } else {
          const text = await response.text().catch(() => 'Failed to load client')
          setError(`Failed to load client: ${text}`)
        }
        setLoading(false)
        return
      }
      const data = await response.json()
      setClient(data)
    } catch (err) {
      setError(`Error loading client: ${err.message}`)
    } finally {
      setLoading(false)
    }
  }

  async function launchScan() {
    if (!confirm(`Launch a full security scan for "${client.name}"? This will scan all authorized domains and IP ranges.`)) {
      return
    }

    setLaunchingScan(true)
    setScanResult(null)

    try {
      // Use the scan/run-all endpoint or create a job
      const response = await apiFetch('/api/scan/run-all', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          client_id: client.id,
        }),
      })

      if (!response.ok) {
        const text = await response.text().catch(() => 'Failed to launch scan')
        setScanResult({
          success: false,
          message: `Failed to launch scan: ${text}`,
        })
        setLaunchingScan(false)
        return
      }

      const data = await response.json()
      setScanResult({
        success: true,
        message: 'Scan launched successfully!',
        job_id: data.job_id || data.id,
        run_id: data.run_id,
      })
    } catch (err) {
      setScanResult({
        success: false,
        message: `Error launching scan: ${err.message}`,
      })
    } finally {
      setLaunchingScan(false)
    }
  }

  if (loading) {
    return (
      <PageShell title="Client Details" subtitle="Loading...">
        <div className="text-center py-12">
          <div className="inline-block w-8 h-8 border-4 border-purple-500 border-t-transparent rounded-full animate-spin" />
          <p className="mt-4 text-slate-400">Loading client...</p>
        </div>
      </PageShell>
    )
  }

  if (error) {
    return (
      <PageShell title="Client Details" subtitle="Error">
        <div className="max-w-2xl mx-auto">
          <div className="p-6 bg-red-900/20 border border-red-500/30 rounded-lg text-red-400">
            {error}
          </div>
          <div className="mt-6 text-center">
            <button
              onClick={() => navigate('/clients')}
              className="px-4 py-2 bg-slate-700 text-white rounded-lg hover:bg-slate-600"
            >
              ← Back to Clients
            </button>
          </div>
        </div>
      </PageShell>
    )
  }

  if (!client) {
    return (
      <PageShell title="Client Details" subtitle="Not Found">
        <div className="max-w-2xl mx-auto text-center py-12">
          <p className="text-slate-400">Client not found</p>
          <button
            onClick={() => navigate('/clients')}
            className="mt-6 px-4 py-2 bg-slate-700 text-white rounded-lg hover:bg-slate-600"
          >
            ← Back to Clients
          </button>
        </div>
      </PageShell>
    )
  }

  const domains = (() => {
    try {
      const parsed = typeof client.domains === 'string' ? JSON.parse(client.domains) : client.domains
      return Array.isArray(parsed) ? parsed : []
    } catch {
      return []
    }
  })()

  const ipRanges = (() => {
    try {
      const parsed = typeof client.ip_ranges === 'string' ? JSON.parse(client.ip_ranges) : client.ip_ranges
      return Array.isArray(parsed) ? parsed : []
    } catch {
      return []
    }
  })()

  const techStack = (() => {
    try {
      const parsed = typeof client.tech_stack === 'string' ? JSON.parse(client.tech_stack) : client.tech_stack
      return Array.isArray(parsed) ? parsed : []
    } catch {
      return []
    }
  })()

  return (
    <PageShell
      title={client.name}
      subtitle="Client Details & Scan Management"
    >
      <div className="max-w-5xl mx-auto space-y-6">
        {/* Header Actions */}
        <div className="flex items-center justify-between">
          <button
            onClick={() => navigate('/clients')}
            className="text-sm text-slate-400 hover:text-slate-300"
          >
            ← Back to Clients
          </button>
          <div className="flex items-center gap-3">
            <Link
              to={`/findings?client_id=${client.id}`}
              className="px-4 py-2 border border-slate-600 text-slate-300 rounded-lg hover:bg-slate-800 transition-colors"
            >
              View Findings
            </Link>
            <button
              onClick={launchScan}
              disabled={launchingScan}
              className="px-6 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors font-medium"
            >
              {launchingScan ? (
                <>
                  <span className="inline-block w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2" />
                  Launching...
                </>
              ) : (
                '▶ Launch Scan'
              )}
            </button>
          </div>
        </div>

        {/* Scan Result Notification */}
        {scanResult && (
          <div
            className={`p-4 rounded-lg border ${
              scanResult.success
                ? 'bg-green-900/20 border-green-500/30 text-green-400'
                : 'bg-red-900/20 border-red-500/30 text-red-400'
            }`}
          >
            <p className="font-medium">{scanResult.message}</p>
            {scanResult.job_id && (
              <p className="mt-2 text-sm">
                Job ID: <code className="font-mono">{scanResult.job_id}</code>
              </p>
            )}
          </div>
        )}

        {/* Client Overview */}
        <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Overview</h3>
          <dl className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <dt className="text-sm text-slate-400">Client Name</dt>
              <dd className="mt-1 text-white font-medium">{client.name}</dd>
            </div>
            {client.contact_email && (
              <div>
                <dt className="text-sm text-slate-400">Contact Email</dt>
                <dd className="mt-1 text-white">{client.contact_email}</dd>
              </div>
            )}
            {client.created_at && (
              <div>
                <dt className="text-sm text-slate-400">Created</dt>
                <dd className="mt-1 text-white">{new Date(client.created_at).toLocaleString()}</dd>
              </div>
            )}
            {client.updated_at && (
              <div>
                <dt className="text-sm text-slate-400">Last Updated</dt>
                <dd className="mt-1 text-white">{new Date(client.updated_at).toLocaleString()}</dd>
              </div>
            )}
          </dl>
        </div>

        {/* Authorized Scope */}
        <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Authorized Scanning Scope</h3>

          <div className="space-y-6">
            <div>
              <h4 className="text-sm font-medium text-slate-300 mb-2">
                Domains ({domains.length})
              </h4>
              {domains.length > 0 ? (
                <div className="bg-slate-900 rounded-lg p-4">
                  <ul className="space-y-1">
                    {domains.map((domain, idx) => (
                      <li key={idx} className="text-green-400 font-mono text-sm">
                        ✓ {domain}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : (
                <p className="text-slate-500 text-sm">No domains specified</p>
              )}
            </div>

            {ipRanges.length > 0 && (
              <div>
                <h4 className="text-sm font-medium text-slate-300 mb-2">
                  IP Ranges ({ipRanges.length})
                </h4>
                <div className="bg-slate-900 rounded-lg p-4">
                  <ul className="space-y-1">
                    {ipRanges.map((range, idx) => (
                      <li key={idx} className="text-blue-400 font-mono text-sm">
                        ✓ {range}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Technology Stack */}
        {techStack.length > 0 && (
          <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-white mb-4">Technology Stack</h3>
            <div className="flex flex-wrap gap-2">
              {techStack.map((tech, idx) => (
                <span
                  key={idx}
                  className="px-3 py-1 bg-purple-600/20 text-purple-400 border border-purple-500/30 rounded-full text-sm"
                >
                  {tech}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Quick Actions */}
        <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Quick Actions</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Link
              to={`/findings?client_id=${client.id}`}
              className="p-4 bg-slate-900 border border-slate-600 rounded-lg hover:border-purple-500/50 transition-colors text-center"
            >
              <div className="text-purple-400 text-2xl mb-2">📊</div>
              <div className="text-white font-medium">View Findings</div>
              <div className="text-slate-500 text-sm mt-1">See all vulnerabilities</div>
            </Link>
            <Link
              to={`/report/${client.id}`}
              className="p-4 bg-slate-900 border border-slate-600 rounded-lg hover:border-purple-500/50 transition-colors text-center"
            >
              <div className="text-purple-400 text-2xl mb-2">📄</div>
              <div className="text-white font-medium">Generate Report</div>
              <div className="text-slate-500 text-sm mt-1">Export PDF/CSV</div>
            </Link>
            <Link
              to={`/attack-surface-graph/${client.id}`}
              className="p-4 bg-slate-900 border border-slate-600 rounded-lg hover:border-purple-500/50 transition-colors text-center"
            >
              <div className="text-purple-400 text-2xl mb-2">🕸️</div>
              <div className="text-white font-medium">Attack Surface</div>
              <div className="text-slate-500 text-sm mt-1">View ASM graph</div>
            </Link>
          </div>
        </div>
      </div>
    </PageShell>
  )
}
