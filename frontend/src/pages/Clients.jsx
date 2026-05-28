import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'

export default function Clients() {
  const [clients, setClients] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [scanningId, setScanningId] = useState(null)
  const [scanToast, setScanToast] = useState(null)

  useEffect(() => {
    loadClients()
  }, [])

  async function loadClients() {
    setLoading(true)
    setError('')
    try {
      const response = await apiFetch('/api/clients')
      if (!response.ok) {
        const text = await response.text().catch(() => 'Failed to load clients')
        setError(`Failed to load clients: ${text}`)
        setLoading(false)
        return
      }
      const data = await response.json()
      // Handle both array response or object with clients array
      const clientList = Array.isArray(data) ? data : (data.clients || [])
      setClients(clientList)
    } catch (err) {
      setError(`Error loading clients: ${err.message}`)
    } finally {
      setLoading(false)
    }
  }

  async function runScan(clientId, clientName) {
    if (!confirm(`Queue the baseline scan bundle (OSINT, ASM, leak hunter, discovery, supply chain, BOLA/IDOR, TLS, WAF bypass) for "${clientName}"?`)) {
      return
    }
    setScanningId(clientId)
    setScanToast(null)
    try {
      const r = await apiFetch(`/api/clients/${clientId}/scan/run-all`, { method: 'POST' })
      const data = await r.json().catch(() => ({}))
      if (!r.ok) {
        setScanToast({ kind: 'error', message: data.detail || `Scan launch failed (HTTP ${r.status})` })
        return
      }
      setScanToast({
        kind: 'ok',
        message: data.message || `Queued ${data.jobs_queued ?? 0} jobs.`,
        jobs_queued: data.jobs_queued ?? 0,
      })
    } catch (err) {
      setScanToast({ kind: 'error', message: err.message || 'Scan launch failed' })
    } finally {
      setScanningId(null)
    }
  }

  async function deleteClient(clientId, clientName) {
    if (!confirm(`Are you sure you want to delete client "${clientName}"? This action cannot be undone.`)) {
      return
    }

    try {
      const response = await apiFetch(`/api/clients/${clientId}`, {
        method: 'DELETE',
      })
      if (!response.ok) {
        const text = await response.text().catch(() => 'Failed to delete client')
        alert(`Failed to delete client: ${text}`)
        return
      }
      // Reload clients list
      loadClients()
    } catch (err) {
      alert(`Error deleting client: ${err.message}`)
    }
  }

  return (
    <PageShell title="Client Management" subtitle="Manage customer organizations and authorized scanning scope">
      <div className="space-y-6">
        {/* Header with Add New button */}
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-2xl font-bold text-white">Clients</h2>
            <p className="text-sm text-slate-400 mt-1">
              {clients.length} client{clients.length !== 1 ? 's' : ''} configured
            </p>
          </div>
          <Link
            to="/clients/new"
            className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 font-medium transition-colors"
          >
            + Add New Client
          </Link>
        </div>

        {/* Error State */}
        {error && (
          <div className="p-4 bg-red-900/20 border border-red-500/30 rounded-lg text-red-400">
            {error}
          </div>
        )}

        {scanToast && (
          <div className={`p-4 rounded-lg border ${
            scanToast.kind === 'ok'
              ? 'bg-emerald-900/20 border-emerald-500/30 text-emerald-300'
              : 'bg-red-900/20 border-red-500/30 text-red-400'
          }`}>
            <div className="font-medium">{scanToast.message}</div>
            {scanToast.kind === 'ok' && (
              <div className="mt-1 text-xs text-slate-400">
                Track progress on the{' '}
                <Link to="/jobs" className="underline hover:text-emerald-200">Jobs Dashboard</Link>{' '}
                or open{' '}
                <Link to="/findings" className="underline hover:text-emerald-200">Findings C2</Link>{' '}
                once scans complete.
              </div>
            )}
          </div>
        )}

        {/* Loading State */}
        {loading && (
          <div className="text-center py-12 text-slate-400">
            <div className="inline-block w-8 h-8 border-4 border-purple-500 border-t-transparent rounded-full animate-spin" />
            <p className="mt-4">Loading clients...</p>
          </div>
        )}

        {/* Empty State */}
        {!loading && !error && clients.length === 0 && (
          <div className="text-center py-12 border-2 border-dashed border-slate-700 rounded-lg">
            <svg className="mx-auto h-12 w-12 text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 48 48">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M34 40h10v-4a6 6 0 00-10.712-3.714M34 40H14m20 0v-4a9.971 9.971 0 00-.712-3.714M14 40H4v-4a6 6 0 0110.713-3.714M14 40v-4c0-1.313.253-2.566.713-3.714m0 0A10.003 10.003 0 0124 26c4.21 0 7.813 2.602 9.288 6.286M30 14a6 6 0 11-12 0 6 6 0 0112 0zm12 6a4 4 0 11-8 0 4 4 0 018 0zm-28 0a4 4 0 11-8 0 4 4 0 018 0z" />
            </svg>
            <h3 className="mt-4 text-lg font-medium text-slate-300">No clients yet</h3>
            <p className="mt-2 text-sm text-slate-500">Get started by adding your first client organization.</p>
            <Link
              to="/clients/new"
              className="mt-6 inline-block px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 font-medium transition-colors"
            >
              Add First Client
            </Link>
          </div>
        )}

        {/* Clients Grid */}
        {!loading && !error && clients.length > 0 && (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
            {clients.map((client) => {
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

              return (
                <div
                  key={client.id}
                  className="p-6 bg-slate-800/50 border border-slate-700 rounded-lg hover:border-purple-500/50 transition-colors group"
                >
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex-1 min-w-0">
                      <h3 className="text-lg font-semibold text-white truncate group-hover:text-purple-400 transition-colors">
                        {client.name}
                      </h3>
                      {client.contact_email && (
                        <p className="text-sm text-slate-400 mt-1 truncate">
                          {client.contact_email}
                        </p>
                      )}
                    </div>
                    <Link
                      to={`/clients/${client.id}`}
                      className="ml-2 px-3 py-1 text-xs bg-purple-600/20 text-purple-400 border border-purple-500/30 rounded hover:bg-purple-600/30 transition-colors"
                    >
                      View
                    </Link>
                  </div>

                  <div className="space-y-2 text-sm">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Domains:</span>
                      <span className="text-white font-medium">{domains.length}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">IP Ranges:</span>
                      <span className="text-white font-medium">{ipRanges.length}</span>
                    </div>
                    {client.created_at && (
                      <div className="flex items-center justify-between pt-2 border-t border-slate-700">
                        <span className="text-slate-500 text-xs">Created:</span>
                        <span className="text-slate-400 text-xs">
                          {new Date(client.created_at).toLocaleDateString()}
                        </span>
                      </div>
                    )}
                  </div>

                  <div className="mt-4 pt-4 border-t border-slate-700 flex items-center justify-between gap-2">
                    <Link
                      to={`/clients/${client.id}`}
                      className="text-sm text-purple-400 hover:text-purple-300 font-medium"
                    >
                      Manage →
                    </Link>
                    <div className="flex items-center gap-3">
                      <button
                        onClick={() => runScan(client.id, client.name)}
                        disabled={scanningId === client.id || domains.length === 0}
                        className="text-sm text-emerald-300 hover:text-emerald-200 disabled:text-slate-500 disabled:cursor-not-allowed transition-colors font-medium"
                        title={domains.length === 0 ? 'Add a domain to enable scanning' : 'Queue baseline scan bundle'}
                      >
                        {scanningId === client.id ? 'Queuing…' : '▶ Scan now'}
                      </button>
                      <button
                        onClick={() => deleteClient(client.id, client.name)}
                        className="text-sm text-red-400 hover:text-red-300 transition-colors"
                        title="Delete client"
                      >
                        Delete
                      </button>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </PageShell>
  )
}
