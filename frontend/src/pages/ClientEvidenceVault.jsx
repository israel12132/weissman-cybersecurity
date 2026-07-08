import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useParams } from 'react-router-dom'
import { createColumnHelper } from '@tanstack/react-table'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanListToolbar from '../components/engine/WeissmanListToolbar'
import DataTable from '../components/ui/DataTable'
import EmptyState from '../components/ui/EmptyState'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import { apiFetch, apiUrl } from '../lib/apiBase'
import { confirmDialog } from '../utils/confirmDialog'
import { useToast } from '../components/ui/Toaster'

const columnHelper = createColumnHelper()

async function fileToBase64(file) {
  const buf = await file.arrayBuffer()
  const bytes = new Uint8Array(buf)
  let binary = ''
  const chunk = 0x8000
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk))
  }
  return btoa(binary)
}

function formatBytes(n) {
  const v = Number(n || 0)
  if (!Number.isFinite(v) || v <= 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  let idx = 0
  let cur = v
  while (cur >= 1024 && idx < units.length - 1) {
    cur /= 1024
    idx += 1
  }
  return `${cur.toFixed(idx === 0 ? 0 : 1)} ${units[idx]}`
}

export default function ClientEvidenceVault() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const { id } = useParams()
  const clientId = useMemo(() => String(id || '').trim(), [id])

  const [client, setClient] = useState(null)
  const [evidence, setEvidence] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [uploading, setUploading] = useState(false)

  const [label, setLabel] = useState('')
  const [notes, setNotes] = useState('')
  const [engagementId, setEngagementId] = useState('')
  const [vulnerabilityId, setVulnerabilityId] = useState('')
  const [file, setFile] = useState(null)

  useEffect(() => {
    if (!clientId) return
    loadAll()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clientId])

  async function loadAll() {
    setLoading(true)
    setError('')
    try {
      const [clientRes, evidenceRes] = await Promise.all([
        apiFetch(`/api/clients/${clientId}`),
        apiFetch(`/api/clients/${clientId}/evidence`),
      ])

      if (!clientRes.ok) {
        setError(t('pages.clientEvidenceVault.load_client_failed', { status: clientRes.status }))
        setLoading(false)
        return
      }
      setClient(await clientRes.json().catch(() => null))

      if (!evidenceRes.ok) {
        const detail = await evidenceRes.text().catch(() => '')
        setError(t('pages.clientEvidenceVault.load_failed', { status: evidenceRes.status, detail }))
        setLoading(false)
        return
      }
      const data = await evidenceRes.json().catch(() => ({}))
      setEvidence(Array.isArray(data.evidence) ? data.evidence : [])
    } catch (e) {
      setError(e?.message || t('pages.clientEvidenceVault.network_error'))
    } finally {
      setLoading(false)
    }
  }

  async function uploadEvidence() {
    if (!file) {
      toast.warning(t('pages.clientEvidenceVault.select_file'))
      return
    }
    if (file.size > 8 * 1024 * 1024) {
      toast.warning(t('pages.clientEvidenceVault.file_too_large'))
      return
    }
    setUploading(true)
    setError('')
    try {
      const dataBase64 = await fileToBase64(file)
      const payload = {
        filename: file.name || 'evidence.bin',
        content_type: file.type || 'application/octet-stream',
        data_base64: dataBase64,
        label: label.trim() || undefined,
        notes: notes.trim() || undefined,
        engagement_id: engagementId.trim() ? Number(engagementId.trim()) : undefined,
        vulnerability_id: vulnerabilityId.trim() ? Number(vulnerabilityId.trim()) : undefined,
      }
      const res = await apiFetch(`/api/clients/${clientId}/evidence`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      const body = await res.json().catch(() => ({}))
      if (!res.ok) {
        setError(body?.detail || body?.error || `Upload failed (HTTP ${res.status})`)
        return
      }
      setLabel('')
      setNotes('')
      setEngagementId('')
      setVulnerabilityId('')
      setFile(null)
      await loadAll()
    } catch (e) {
      setError(e?.message || t('pages.clientEvidenceVault.upload_failed'))
    } finally {
      setUploading(false)
    }
  }

  async function deleteEvidence(item) {
    const ok = await confirmDialog({
      title: t('pages.clientEvidenceVault.delete_title'),
      message: t('pages.clientEvidenceVault.delete_confirm', { name: item.filename }),
      confirmLabel: t('common.delete'),
      cancelLabel: t('common.cancel'),
      variant: 'danger',
    })
    if (!ok) return
    try {
      const res = await apiFetch(`/api/evidence/${item.id}`, { method: 'DELETE' })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        toast.error(data?.detail || data?.error || `Delete failed (HTTP ${res.status})`)
        return
      }
      await loadAll()
      toast.success(t('pages.clientEvidenceVault.delete_success'))
    } catch (e) {
      toast.error(e?.message || t('pages.clientEvidenceVault.delete_failed'))
    }
  }

  function downloadEvidence(item) {
    window.open(apiUrl(`/api/evidence/${item.id}/download`), '_blank', 'noopener,noreferrer')
  }

  const listFindings = useMemo(() => evidence.map((item) => ({
    id: item.id,
    severity: 'info',
    title: item.filename || item.title || item.id,
    type: item.kind || 'evidence',
    description: item.description || formatBytes(item.size_bytes),
    resource: item.sha256 || '',
  })), [evidence])

  const {
    exportCsv,
    filteredFindings,
    searchQuery,
    setSearchQuery,
  } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'weissman-client-evidence',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.resource}`,
  })

  const visibleEvidence = useMemo(() => {
    if (!searchQuery.trim()) return evidence
    const ids = new Set(filteredFindings.map((f) => String(f.id)))
    return evidence.filter((item) => ids.has(String(item.id)))
  }, [evidence, filteredFindings, searchQuery])

  const columns = useMemo(() => [
    columnHelper.accessor((ev) => ev.filename, {
      id: 'file',
      header: t('pages.clientEvidenceVault.col_file'),
      cell: ({ row }) => {
        const ev = row.original
        return (
          <div className="text-white">
            <div className="font-medium">{ev.filename}</div>
            <div className="text-[11px] text-slate-500">{new Date(ev.created_at).toLocaleString()}</div>
          </div>
        )
      },
    }),
    columnHelper.accessor((ev) => ev.label || '', {
      id: 'label',
      header: t('pages.clientEvidenceVault.col_label'),
      cell: ({ row }) => {
        const ev = row.original
        return <span className="text-slate-200">{ev.label || <span className="text-slate-600">—</span>}</span>
      },
    }),
    columnHelper.accessor((ev) => Number(ev.size_bytes || 0), {
      id: 'size',
      header: t('pages.clientEvidenceVault.col_size'),
      cell: ({ row }) => (
        <span className="text-slate-200 font-mono">{formatBytes(row.original.size_bytes)}</span>
      ),
    }),
    columnHelper.accessor((ev) => ev.sha256_hex || '', {
      id: 'sha',
      header: t('pages.clientEvidenceVault.col_sha'),
      cell: ({ row }) => (
        <span className="text-slate-300 font-mono text-[11px]">
          {(row.original.sha256_hex || '').slice(0, 16)}…
        </span>
      ),
    }),
    columnHelper.display({
      id: 'links',
      header: t('pages.clientEvidenceVault.col_links'),
      enableSorting: false,
      cell: ({ row }) => {
        const ev = row.original
        return (
          <div className="text-slate-300 font-mono text-[11px]">
            <div>{t('pages.clientEvidenceVault.eng_link', { id: ev.engagement_id ?? '—' })}</div>
            <div>{t('pages.clientEvidenceVault.vuln_link', { id: ev.vulnerability_id ?? '—' })}</div>
          </div>
        )
      },
    }),
    columnHelper.display({
      id: 'actions',
      header: t('pages.clientEvidenceVault.col_actions'),
      enableSorting: false,
      cell: ({ row }) => {
        const ev = row.original
        return (
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => downloadEvidence(ev)}
              className="px-3 py-1 text-xs bg-slate-700 text-white rounded hover:bg-slate-600"
            >
              {t('pages.clientEvidenceVault.download')}
            </button>
            <button
              type="button"
              onClick={() => deleteEvidence(ev)}
              className="px-3 py-1 text-xs bg-red-900/30 text-red-200 rounded hover:bg-red-900/50 border border-red-500/20"
            >
              {t('pages.clientEvidenceVault.delete')}
            </button>
          </div>
        )
      },
    }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
  ], [t])

  if (loading) {
    return (
      <PageShell title={t('pages.clientEvidenceVault.title')} subtitle={t('pages.clientEngagements.loading_subtitle')}>
        <div className="text-center py-12">
          <div className="inline-block w-8 h-8 border-4 border-purple-500 border-t-transparent rounded-full animate-spin" />
          <p className="mt-4 text-slate-400">{t('pages.clientEvidenceVault.loading')}</p>
        </div>
      </PageShell>
    )
  }

  return (
    <PageShell
      title={client?.name
        ? t('pages.clientEvidenceVault.title_with_client', { name: client.name })
        : t('pages.clientEvidenceVault.title')}
      subtitle={t('pages.clientEvidenceVault.subtitle')}
      actions={(
        <ShellScanActions
          onRefresh={loadAll}
          onExport={exportCsv}
          refreshLoading={loading}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      <div className="max-w-5xl mx-auto space-y-6">
        <div className="flex items-center justify-between">
          <Link to={`/clients/${clientId}`} className="text-sm text-slate-400 hover:text-slate-200">
            {t('pages.clientEvidenceVault.back_to_client')}
          </Link>
          <div className="text-xs text-slate-500 font-mono">{t('pages.clientEvidenceVault.client_id', { id: clientId })}</div>
        </div>

        {error && (
          <div className="p-4 bg-red-900/20 border border-red-500/30 rounded-lg text-red-300">
            {error}
          </div>
        )}

        <div className="p-6 bg-slate-800/40 border border-slate-700 rounded-xl">
          <div className="flex items-center justify-between gap-4">
            <div>
              <h2 className="text-lg font-semibold text-white">{t('pages.clientEvidenceVault.upload_heading')}</h2>
              <p className="text-xs text-slate-400 mt-1">{t('pages.clientEvidenceVault.upload_body')}</p>
            </div>
            <button
              type="button"
              onClick={uploadEvidence}
              disabled={uploading}
              className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:opacity-50"
            >
              {uploading ? t('pages.clientEvidenceVault.uploading') : t('pages.clientEvidenceVault.upload')}
            </button>
          </div>

          <div className="mt-5 grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="md:col-span-2">
              <label className="block text-xs text-slate-400 mb-1">{t('pages.clientEvidenceVault.file')}</label>
              <input
                type="file"
                className="w-full px-3 py-2 bg-slate-900/60 border border-slate-700 rounded-lg text-white"
                onChange={(e) => setFile(e.target.files?.[0] || null)}
              />
              {file && (
                <div className="mt-1 text-[11px] text-slate-400 font-mono">
                  {file.name} — {formatBytes(file.size)}
                </div>
              )}
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">{t('pages.clientEvidenceVault.label_optional')}</label>
              <input
                className="w-full px-3 py-2 bg-slate-900/60 border border-slate-700 rounded-lg text-white"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                placeholder={t('pages.clientEvidenceVault.label_placeholder')}
              />
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">{t('pages.clientEvidenceVault.engagement_id_optional')}</label>
              <input
                className="w-full px-3 py-2 bg-slate-900/60 border border-slate-700 rounded-lg text-white font-mono"
                value={engagementId}
                onChange={(e) => setEngagementId(e.target.value)}
                placeholder="123"
              />
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">{t('pages.clientEvidenceVault.vuln_id_optional')}</label>
              <input
                className="w-full px-3 py-2 bg-slate-900/60 border border-slate-700 rounded-lg text-white font-mono"
                value={vulnerabilityId}
                onChange={(e) => setVulnerabilityId(e.target.value)}
                placeholder="456"
              />
            </div>

            <div className="md:col-span-2">
              <label className="block text-xs text-slate-400 mb-1">{t('pages.clientEvidenceVault.notes_optional')}</label>
              <textarea
                className="w-full min-h-24 px-3 py-2 bg-slate-900/60 border border-slate-700 rounded-lg text-white"
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder={t('pages.clientEvidenceVault.notes_placeholder')}
              />
            </div>
          </div>
        </div>

        <div className="p-6 bg-slate-800/40 border border-slate-700 rounded-xl">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-white">{t('pages.clientEvidenceVault.items_heading')}</h2>
            <span className="text-xs text-slate-500">{t('pages.clientEvidenceVault.total', { count: evidence.length })}</span>
          </div>

          {evidence.length === 0 ? (
            <div className="mt-4 text-sm text-slate-400">{t('pages.clientEvidenceVault.empty')}</div>
          ) : (
            <>
            <WeissmanListToolbar
              className="mt-4"
              searchQuery={searchQuery}
              onSearchChange={setSearchQuery}
              resultCount={visibleEvidence.length}
              totalCount={evidence.length}
            />
            {visibleEvidence.length === 0 ? (
              <EmptyState
                icon="search"
                title={t('weissmanFindings.filtered_title')}
                body={t('weissmanFindings.filtered_body')}
                compact
              />
            ) : (
            <div className="mt-4">
              <DataTable
                columns={columns}
                data={visibleEvidence}
                animateRows={false}
                getRowId={(item) => item.id}
              />
            </div>
            )}
            </>
          )}
        </div>
      </div>
    </PageShell>
  )
}

