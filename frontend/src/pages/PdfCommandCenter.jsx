/**
 * PDF Intelligence Command — collect every live report artifact and compose a
 * professional board/regulator pack. Live-only: empty corpus fails visibly.
 *
 * Route: /pdf-intelligence
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { FileStack, Lock, Search, ShieldCheck, Sparkles } from 'lucide-react'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import EmptyState from '../components/ui/EmptyState'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import Button from '../components/ui/Button'
import { apiFetch } from '../utils/apiFetch'
import { useClient } from '../context/ClientContext'
import ScopedClientControl from '../components/clients/ScopedClientControl'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'

const NS = 'pages.pdfCommandCenter'

export default function PdfCommandCenter() {
  const { t } = useTranslation()
  const { selectedClientId, setSelectedClientId, clients } = useClient()
  const [snap, setSnap] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [sections, setSections] = useState([])
  const [title, setTitle] = useState('')
  const [composing, setComposing] = useState(false)
  const [composeError, setComposeError] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const qs = selectedClientId ? `?client_id=${encodeURIComponent(selectedClientId)}` : ''
      const d = await apiFetch(`/api/pdf-intelligence${qs}`)
      setSnap(d)
      const catalog = Array.isArray(d?.section_catalog) ? d.section_catalog : []
      setSections((prev) => {
        if (prev.length) {
          return catalog.map((c) => {
            const old = prev.find((p) => p.id === c.id)
            return { ...c, enabled: old ? old.enabled : c.enabled }
          })
        }
        return catalog
      })
    } catch (e) {
      setError(e.message || t(`${NS}.load_failed`))
      setSnap(null)
    } finally {
      setLoading(false)
    }
  }, [selectedClientId, t])

  useEffect(() => {
    load()
  }, [load])

  const corpus = Array.isArray(snap?.corpus) ? snap.corpus : []
  const frameworks = Array.isArray(snap?.frameworks) ? snap.frameworks : []
  const findings = snap?.findings || {}

  const filteredCorpus = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return corpus
    return corpus.filter((c) => `${c.kind} ${c.title} ${c.pdf_path || ''}`.toLowerCase().includes(q))
  }, [corpus, search])

  const toggleSection = (id) => {
    setSections((prev) => prev.map((s) => (s.id === id ? { ...s, enabled: !s.enabled } : s)))
  }

  const exportCsv = () => {
    const header = ['id', 'kind', 'title', 'client_id', 'created_at', 'finding_count', 'pdf_path']
    const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`
    const lines = [
      header.join(','),
      ...corpus.map((c) => header.map((k) => esc(c[k])).join(',')),
    ]
    const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `weissman-pdf-corpus-${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  const compose = async () => {
    setComposing(true)
    setComposeError('')
    try {
      const res = await apiFetch('/api/pdf-intelligence/compose', {
        method: 'POST',
        raw: true,
        body: {
          client_id: selectedClientId ? Number(selectedClientId) : null,
          title: title.trim() || undefined,
          sections: sections.map((s) => ({ id: s.id, enabled: !!s.enabled })),
        },
      })
      if (!(res instanceof Response)) {
        throw new Error(t(`${NS}.compose_failed`))
      }
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `Weissman_Intelligence_Pack_${new Date().toISOString().slice(0, 10)}.pdf`
      a.rel = 'noopener'
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
    } catch (e) {
      if (e?.response) {
        const body = await e.response.json().catch(() => ({}))
        setComposeError(body.detail || body.error || t(`${NS}.compose_failed`))
      } else {
        setComposeError(e.message || t(`${NS}.compose_failed`))
      }
    } finally {
      setComposing(false)
    }
  }

  const empty = Boolean(snap?.empty_reason)

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      badge={t(`${NS}.badge`)}
      badgeColor="#f59e0b"
      icon={<FileStack />}
      actions={(
        <ShellScanActions
          onRefresh={load}
          onExport={exportCsv}
          refreshLoading={loading}
          exportDisabled={!corpus.length}
          exportLabel={t(`${NS}.export_csv`)}
        />
      )}
    >
      <div className="space-y-6">
        <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>

        <div className="flex flex-wrap items-center gap-3">
          <ScopedClientControl
            value={selectedClientId}
            onChange={setSelectedClientId}
            clients={clients}
            placeholder={t(`${NS}.all_clients`)}
            allowEmpty
            className="bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-xs font-mono text-[var(--text-secondary)] min-w-[12rem]"
          />
          <label className="relative flex-1 min-w-[12rem]">
            <Search className="w-3.5 h-3.5 absolute start-3 top-1/2 -translate-y-1/2 text-[var(--text-muted)]" />
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder={t(`${NS}.search_placeholder`)}
              className="w-full ps-8 pe-3 py-1.5 rounded-lg bg-[var(--bg-3)] border border-[var(--border-default)] text-xs font-mono text-[var(--text-secondary)]"
            />
          </label>
        </div>

        {loading ? (
          <SkeletonWidgetGrid count={4} />
        ) : error ? (
          <EmptyState icon="alert" title={t(`${NS}.load_failed`)} description={error} />
        ) : (
          <>
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
              <ExecutiveWidget label={t(`${NS}.kpi_artifacts`)} value={corpus.length} accent="#f59e0b" />
              <ExecutiveWidget label={t(`${NS}.kpi_findings`)} value={findings.total ?? 0} accent="#ef4444" hint={`C ${findings.critical ?? 0} · H ${findings.high ?? 0}`} />
              <ExecutiveWidget label={t(`${NS}.kpi_frameworks`)} value={frameworks.length} accent="#22d3ee" />
              <ExecutiveWidget
                label={t(`${NS}.kpi_scope`)}
                value={snap?.client_name || t(`${NS}.tenant_wide`)}
                accent="#a78bfa"
              />
            </div>

            {empty && (
              <EmptyState
                icon="file"
                title={t(`${NS}.empty_title`)}
                description={snap.empty_reason}
              />
            )}

            <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
              <section className="xl:col-span-5 rounded-2xl border border-[var(--border-default)] bg-black/30 p-4 space-y-3">
                <h2 className="text-xs font-mono uppercase tracking-[0.18em] text-amber-300/80 flex items-center gap-2">
                  <FileStack className="w-3.5 h-3.5" /> {t(`${NS}.corpus_title`)}
                </h2>
                {filteredCorpus.length === 0 ? (
                  <p className="text-xs text-[var(--text-muted)]">{t(`${NS}.corpus_empty`)}</p>
                ) : (
                  <ul className="space-y-2 max-h-[28rem] overflow-y-auto">
                    {filteredCorpus.map((c) => (
                      <li
                        key={c.id}
                        className="rounded-xl border border-white/5 bg-white/[0.02] px-3 py-2"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-sm text-[var(--text-primary)] truncate">{c.title}</span>
                          <span className="text-[9px] font-mono uppercase tracking-widest text-amber-400/70 shrink-0">
                            {c.kind}
                          </span>
                        </div>
                        <div className="text-[10px] font-mono text-[var(--text-muted)] mt-1 truncate">
                          {c.pdf_path || t(`${NS}.no_path`)} · {t(`${NS}.findings_n`, { count: c.finding_count ?? 0 })}
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </section>

              <section className="xl:col-span-7 rounded-2xl border border-cyan-500/20 bg-gradient-to-br from-cyan-500/[0.04] to-black/40 p-4 space-y-4">
                <h2 className="text-xs font-mono uppercase tracking-[0.18em] text-cyan-300/80 flex items-center gap-2">
                  <Sparkles className="w-3.5 h-3.5" /> {t(`${NS}.editor_title`)}
                </h2>
                <label className="block">
                  <span className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)]">
                    {t(`${NS}.doc_title`)}
                  </span>
                  <input
                    type="text"
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                    placeholder={t(`${NS}.doc_title_placeholder`)}
                    className="mt-1 w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-default)] px-3 py-2 text-sm text-white"
                  />
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {sections.map((s) => (
                    <button
                      key={s.id}
                      type="button"
                      onClick={() => toggleSection(s.id)}
                      className={`text-start rounded-xl border px-3 py-2 transition-colors ${
                        s.enabled
                          ? 'border-cyan-400/40 bg-cyan-500/10 text-cyan-100'
                          : 'border-white/5 bg-white/[0.02] text-[var(--text-muted)]'
                      }`}
                    >
                      <div className="text-[11px] font-semibold">{s.label || s.id}</div>
                      <div className="text-[9px] font-mono uppercase tracking-widest mt-0.5">
                        {s.enabled ? t(`${NS}.section_on`) : t(`${NS}.section_off`)}
                      </div>
                    </button>
                  ))}
                </div>
                <div className="flex flex-wrap items-center gap-3">
                  <Button
                    type="button"
                    onClick={compose}
                    disabled={composing || empty}
                    className="inline-flex items-center gap-2"
                  >
                    <Lock className="w-3.5 h-3.5" />
                    {composing ? t(`${NS}.composing`) : t(`${NS}.compose`)}
                  </Button>
                  {composeError && (
                    <span className="text-xs text-rose-300 font-mono" role="alert">{composeError}</span>
                  )}
                </div>
              </section>
            </div>

            <section className="rounded-2xl border border-[var(--border-default)] bg-black/25 p-4">
              <h2 className="text-xs font-mono uppercase tracking-[0.18em] text-[var(--text-muted)] mb-3 flex items-center gap-2">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" /> {t(`${NS}.frameworks_title`)}
              </h2>
              {frameworks.length === 0 ? (
                <p className="text-xs text-[var(--text-muted)]">{t(`${NS}.frameworks_empty`)}</p>
              ) : (
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                  {frameworks.map((fw) => (
                    <div key={fw.framework} className="rounded-xl border border-white/5 px-3 py-2">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-sm text-[var(--text-primary)]">{fw.framework}</span>
                        <span className="text-sm font-mono text-emerald-300 tabular-nums">{fw.compliance_percent}%</span>
                      </div>
                      <div className="text-[10px] font-mono text-[var(--text-muted)] mt-1">
                        {t(`${NS}.controls_line`, {
                          mapped: fw.total_mapped_controls,
                          violated: fw.violated_controls,
                        })}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </section>
          </>
        )}
      </div>
    </PageShell>
  )
}
