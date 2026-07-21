import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { createColumnHelper } from '@tanstack/react-table'
import { apiUrl, apiFetch } from '../../lib/apiBase'
import Button from '../ui/Button'
import DataTable from '../ui/DataTable'

const columnHelper = createColumnHelper()
const VV = 'components.ceo.vaccineVault'

export default function CeoVaccineVault() {
  const { t } = useTranslation()
  const [rows, setRows] = useState([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState('')
  const [selected, setSelected] = useState(null)
  const [tab, setTab] = useState('chain')
  const [matchBusy, setMatchBusy] = useState(false)
  const [matchMsg, setMatchMsg] = useState('')

  const tabs = [
    { id: 'chain', label: t('components.ceo.vaccineVault.tabChain') },
    { id: 'transcript', label: t('components.ceo.vaccineVault.tabTranscript') },
    { id: 'patch', label: t('components.ceo.vaccineVault.tabPatch') },
    { id: 'sig', label: t('components.ceo.vaccineVault.tabSig') },
  ]

  const load = useCallback(async () => {
    setLoading(true)
    setErr('')
    try {
      const r = await apiFetch('/api/ceo/vault?limit=100&offset=0')
      const d = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(d.detail || r.statusText)
      setRows(Array.isArray(d) ? d : [])
    } catch (e) {
      setErr(e.message || t('components.ceo.vaccineVault.loadFailed'))
      setRows([])
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => {
    load()
  }, [load])

  const columns = useMemo(
    () => [
      columnHelper.accessor('id', {
        header: t(`${VV}.colId`),
        cell: (info) => <span className="text-cyan-300/90">{info.getValue()}</span>,
      }),
      columnHelper.accessor('tech_fingerprint', {
        header: t(`${VV}.colFingerprint`),
        cell: (info) => (
          <span className="max-w-[180px] truncate block" title={info.getValue()}>
            {info.getValue()}
          </span>
        ),
      }),
      columnHelper.accessor('severity', { header: t(`${VV}.colSeverity`) }),
      columnHelper.accessor((r) => (r.preemptive_validated ? t(`${VV}.yes`) : t(`${VV}.no`)), {
        id: 'validated',
        header: t(`${VV}.colValidated`),
      }),
      columnHelper.accessor('component_ref', {
        header: t(`${VV}.colComponent`),
        cell: (info) => (
          <span className="max-w-[200px] truncate block" title={info.getValue()}>
            {info.getValue()}
          </span>
        ),
      }),
    ],
    [t],
  )

  const runMatch = async () => {
    if (!selected) return
    setMatchBusy(true)
    setMatchMsg('')
    try {
      const path = '/api/ceo/genesis/vault/' + encodeURIComponent(selected.id) + '/match'
      const r = await apiFetch(path, { method: 'POST' })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(d.detail || r.statusText)
      setMatchMsg(JSON.stringify(d, null, 2))
    } catch (e) {
      setMatchMsg(e.message || t('components.ceo.vaccineVault.matchFailed'))
    } finally {
      setMatchBusy(false)
    }
  }

  return (
    <div className="rounded-lg border border-white/10 bg-black/35 overflow-hidden">
      <div className="px-4 py-3 border-b border-white/10 flex flex-wrap justify-between gap-2 items-center">
        <h2 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-widest">
          {t('components.ceo.vaccineVault.title')}
        </h2>
        <div className="flex gap-2">
          <a
            href={apiUrl('/api/ceo/vault/export/criticals')}
            className="text-xs font-mono px-3 py-1.5 rounded border border-white/20 text-[var(--text-secondary)] hover:bg-white/5"
            download
          >
            {t('components.ceo.vaccineVault.exportCriticals')}
          </a>
          <Button variant="unstyled"
            type="button"
            onClick={load}
            className="text-xs font-mono px-3 py-1.5 rounded border border-cyan-500/30 text-cyan-200 hover:bg-cyan-950/40"
          >
            {t('components.ceo.vaccineVault.refresh')}
          </Button>
        </div>
      </div>
      {loading && <p className="p-4 text-xs text-[var(--text-muted)] font-mono">{t('components.ceo.vaccineVault.loading')}</p>}
      {err && <p className="p-4 text-xs text-red-400 font-mono">{err}</p>}
      {!loading && !err && (
        <DataTable
          id="ceo-vaccine-vault-table"
          columns={columns}
          data={rows}
          getRowId={(r) => r.id}
          selectedRowId={selected?.id}
          onRowClick={(row) => {
            setSelected(row.original)
            setTab('chain')
            setMatchMsg('')
          }}
          animateRows={false}
        />
      )}

      {selected && (
        <div className="border-t border-white/10 bg-[var(--bg-0)]/80 p-4 space-y-3">
          <div className="flex flex-wrap gap-2 items-center justify-between">
            <span className="text-xs font-mono text-[var(--text-tertiary)]">
              {t('components.ceo.vaccineVault.rowLabel', { id: selected.id })}
            </span>
            <Button variant="unstyled"
              type="button"
              disabled={matchBusy}
              onClick={runMatch}
              className="text-xs font-mono px-3 py-2 rounded bg-violet-950/80 border border-violet-400/40 text-violet-100 disabled:opacity-50"
            >
              {matchBusy
                ? t('components.ceo.vaccineVault.running')
                : t('components.ceo.vaccineVault.runMatch')}
            </Button>
          </div>
          {matchMsg && (
            <pre className="text-[10px] font-mono text-[var(--text-tertiary)] whitespace-pre-wrap break-words max-h-40 overflow-y-auto border border-white/10 rounded p-2">
              {matchMsg}
            </pre>
          )}
          <div className="flex gap-1 border-b border-white/10 pb-2">
            {tabs.map((tabItem) => (
              <Button variant="unstyled"
                key={tabItem.id}
                type="button"
                onClick={() => setTab(tabItem.id)}
                className={
                  'text-[10px] font-mono uppercase px-3 py-1 rounded-t ' +
                  (tab === tabItem.id ? 'bg-white/10 text-cyan-200' : 'text-[var(--text-muted)] hover:text-[var(--text-secondary)]')
                }
              >
                {tabItem.label}
              </Button>
            ))}
          </div>
          <div className="min-h-[200px] max-h-[360px] overflow-y-auto text-[11px] font-mono">
            {tab === 'chain' && (
              <pre className="whitespace-pre-wrap break-words text-[var(--text-secondary)]">
                {JSON.stringify(selected.attack_chain_json, null, 2)}
              </pre>
            )}
            {tab === 'transcript' && (
              <pre className="whitespace-pre-wrap break-words text-[var(--text-secondary)]">
                {JSON.stringify(selected.council_transcript, null, 2)}
              </pre>
            )}
            {tab === 'patch' && (
              <pre className="whitespace-pre-wrap break-words text-emerald-200/90 bg-black/50 p-3 rounded border border-emerald-500/20">
                {selected.remediation_patch || '—'}
              </pre>
            )}
            {tab === 'sig' && (
              <pre className="whitespace-pre-wrap break-words text-amber-200/90 bg-black/50 p-3 rounded border border-amber-500/20">
                {selected.detection_signature || '—'}
              </pre>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
