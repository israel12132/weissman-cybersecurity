import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { apiFetch } from '../lib/apiBase'
import { formatApiErrorFromBody, formatApiErrorResponse } from '../lib/apiError'

/**
 * Visual SOAR playbook editor.
 *
 *   ┌────────────┐  ┌──────────────────────┐  ┌──────────────────────┐
 *   │ Playbooks  │  │ Trigger + Actions    │  │ Run history          │
 *   │ (left col) │  │ (centre — JSON edit) │  │ (right col)          │
 *   └────────────┘  └──────────────────────┘  └──────────────────────┘
 *
 * Talks to:
 *   GET    /api/playbooks
 *   POST   /api/playbooks
 *   PATCH  /api/playbooks/:id
 *   DELETE /api/playbooks/:id
 *   POST   /api/playbooks/fire        (dry-run support)
 *   GET    /api/playbooks/:id/runs
 *
 * Live data only; no fake examples. An "Insert example" button populates the
 * editor with a real-world template the analyst can adapt.
 */

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']
const ACTION_KINDS = [
  { kind: 'set_status',   label: 'Set Status',     params: { status: 'IN_PROGRESS' } },
  { kind: 'slack_notify', label: 'Slack / Webhook', params: { url: '', template: '{{severity}}: {{title}} on {{target}}' } },
  { kind: 'webhook',      label: 'HTTP Webhook',    params: { url: '', template: '{{title}}' } },
  { kind: 'open_pr',      label: 'Auto-PR',         params: { title: 'Auto-fix: {{title}}' } },
  { kind: 'isolate_host', label: 'Isolate Host',    params: { target: '{{target}}', duration_seconds: 900 } },
  { kind: 'page_oncall',  label: 'Page On-call',    params: { team: 'sec-oncall', severity: '{{severity}}' } },
  { kind: 'http_post',    label: 'HTTP POST',       params: { url: '', body: { } } },
]

const EXAMPLE_PLAYBOOK = {
  name: 'Critical KEV \u2192 isolate + page',
  description: 'Any critical finding with a CISA-KEV listed CVE on an internet-exposed asset isolates the host and pages on-call.',
  enabled: true,
  trigger: {
    severity: ['critical'],
    kev: true,
    exposed: true,
    cooldown_seconds: 3600,
  },
  actions: [
    { kind: 'set_status',   params: { status: 'IN_PROGRESS' } },
    { kind: 'isolate_host', params: { target: '{{target}}', duration_seconds: 1800 } },
    { kind: 'page_oncall',  params: { team: 'sec-oncall', severity: 'critical' } },
    { kind: 'slack_notify', params: { template: 'KEV CRITICAL on {{target}}: {{title}} (cvss={{cvss}} epss={{epss}})' } },
  ],
}

function StatusPill({ status }) {
  const color = {
    success:     '#22c55e',
    partial:     '#f59e0b',
    failed:      '#ef4444',
    dry_run:     '#22d3ee',
    skipped_dedup: '#94a3b8',
    '':          '#64748b',
  }[status || ''] || '#64748b'
  return (
    <span
      className="inline-block px-1.5 py-0.5 rounded text-[9px] font-mono uppercase tracking-widest"
      style={{ background: `${color}22`, color, border: `1px solid ${color}55` }}
    >
      {status || '\u2014'}
    </span>
  )
}

function SectionTitle({ children }) {
  return (
    <h3 className="text-[10px] font-mono uppercase tracking-[0.2em] text-white/55 mb-1.5">
      {children}
    </h3>
  )
}

export default function PlaybookBuilder() {
  const [list, setList] = useState([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(null)
  const [selected, setSelected] = useState(null)
  const [draft, setDraft] = useState(null)
  const [saving, setSaving] = useState(false)
  const [statusMsg, setStatusMsg] = useState(null)
  const [runs, setRuns] = useState([])
  const [fireResult, setFireResult] = useState(null)

  const refresh = useCallback(async () => {
    setLoading(true)
    setLoadError(null)
    try {
      const r = await apiFetch('/api/playbooks')
      const d = await r.json().catch(() => ({}))
      if (!r.ok) {
        setList([])
        setLoadError(formatApiErrorFromBody(d, r.status))
        return
      }
      setList(Array.isArray(d?.playbooks) ? d.playbooks : [])
    } catch (e) {
      setList([])
      setLoadError(e?.message || 'Network error')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { refresh() }, [refresh])

  // When a playbook is selected, pull its history.
  useEffect(() => {
    if (!selected) { setRuns([]); return }
    let abort = false
    apiFetch(`/api/playbooks/${selected.id}/runs?limit=20`)
      .then((r) => r.json())
      .then((d) => { if (!abort) setRuns(d?.runs || []) })
      .catch(() => { if (!abort) setRuns([]) })
    return () => { abort = true }
  }, [selected])

  const startNew = () => {
    setSelected(null)
    setDraft({
      name: '',
      description: '',
      enabled: false,
      trigger: { severity: [], cooldown_seconds: 3600 },
      actions: [],
    })
    setStatusMsg(null)
    setFireResult(null)
  }

  const startEdit = (pb) => {
    setSelected(pb)
    setDraft({
      name: pb.name,
      description: pb.description || '',
      enabled: !!pb.enabled,
      trigger: pb.trigger || {},
      actions: pb.actions || [],
    })
    setStatusMsg(null)
    setFireResult(null)
  }

  const insertExample = () => {
    setSelected(null)
    setDraft(JSON.parse(JSON.stringify(EXAMPLE_PLAYBOOK)))
    setStatusMsg({ kind: 'info', text: 'Loaded example template. Tweak and Save.' })
    setFireResult(null)
  }

  const save = async () => {
    if (!draft?.name?.trim()) { setStatusMsg({ kind: 'err', text: 'Name required' }); return }
    setSaving(true)
    setStatusMsg(null)
    const body = JSON.stringify({
      name: draft.name.trim(),
      description: draft.description || '',
      enabled: !!draft.enabled,
      trigger: draft.trigger || {},
      actions: draft.actions || [],
    })
    try {
      const url = selected ? `/api/playbooks/${selected.id}` : '/api/playbooks'
      const method = selected ? 'PATCH' : 'POST'
      const r = await apiFetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body,
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) {
        setStatusMsg({ kind: 'err', text: d?.detail || `HTTP ${r.status}` })
      } else {
        setStatusMsg({ kind: 'ok', text: selected ? 'Updated' : `Created (id ${d.id})` })
        await refresh()
        if (!selected && d.id) {
          // Auto-select the newly created one for further edits.
          const r2 = await apiFetch('/api/playbooks').then((x) => x.json()).catch(() => ({}))
          const fresh = (r2?.playbooks || []).find((p) => p.id === d.id)
          if (fresh) startEdit(fresh)
        }
      }
    } catch (e) {
      setStatusMsg({ kind: 'err', text: e?.message || 'network error' })
    } finally {
      setSaving(false)
    }
  }

  const remove = async () => {
    if (!selected) return
    if (!window.confirm(`Delete "${selected.name}"?`)) return
    try {
      const r = await apiFetch(`/api/playbooks/${selected.id}`, { method: 'DELETE' })
      if (r.ok) {
        setSelected(null); setDraft(null)
        await refresh()
      } else {
        setStatusMsg({ kind: 'err', text: await formatApiErrorResponse(r) })
      }
    } catch (e) {
      setStatusMsg({ kind: 'err', text: e?.message || 'Network error' })
    }
  }

  const dryRun = async () => {
    if (!draft) return
    setStatusMsg(null)
    setFireResult({ loading: true })
    const sampleEvent = {
      kind: 'finding_persisted',
      tenant_id: 0,
      client_id: 1,
      finding_id: 999_999,
      cluster_id: null,
      title: 'Sample event for dry-run',
      severity: (draft.trigger?.severity?.[0]) || 'critical',
      source: (draft.trigger?.engines?.[0]) || 'asm',
      target: 'https://example.com/probe',
      status: 'OPEN',
      cvss: 9.8,
      epss: draft.trigger?.epss_min ?? 0.85,
      kev: !!draft.trigger?.kev,
      kev_known_ransomware: !!draft.trigger?.kev,
      cve: 'CVE-2024-12345',
      signature_hash: 'preview',
      internet_exposed: !!draft.trigger?.exposed,
    }
    try {
      const r = await apiFetch('/api/playbooks/fire', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ event: sampleEvent, dry_run: true }),
      })
      const d = await r.json()
      setFireResult({ loading: false, ok: r.ok, ...d })
    } catch (e) {
      setFireResult({ loading: false, ok: false, detail: e?.message || 'network error' })
    }
  }

  const updateTrigger = (patch) =>
    setDraft((d) => ({ ...d, trigger: { ...(d.trigger || {}), ...patch } }))

  const toggleSev = (s) =>
    updateTrigger({
      severity: (draft.trigger?.severity || []).includes(s)
        ? draft.trigger.severity.filter((x) => x !== s)
        : [...(draft.trigger?.severity || []), s],
    })

  const addAction = (kind) => {
    const template = ACTION_KINDS.find((a) => a.kind === kind) || ACTION_KINDS[0]
    setDraft((d) => ({
      ...d,
      actions: [...(d.actions || []), JSON.parse(JSON.stringify({ kind: template.kind, params: template.params }))],
    }))
  }
  const moveAction = (i, dir) => {
    setDraft((d) => {
      const arr = [...(d.actions || [])]
      const j = i + dir
      if (j < 0 || j >= arr.length) return d
      ;[arr[i], arr[j]] = [arr[j], arr[i]]
      return { ...d, actions: arr }
    })
  }
  const removeAction = (i) =>
    setDraft((d) => ({ ...d, actions: (d.actions || []).filter((_, k) => k !== i) }))

  const updateActionParams = (i, json) => {
    setDraft((d) => {
      const arr = [...(d.actions || [])]
      arr[i] = { ...arr[i], params: json }
      return { ...d, actions: arr }
    })
  }

  const filterSummary = useMemo(() => {
    if (!list.length) return '0 playbooks'
    const enabled = list.filter((p) => p.enabled).length
    const fails = list.reduce((a, b) => a + (b.failure_count || 0), 0)
    return `${list.length} playbooks · ${enabled} enabled · ${fails} failures all-time`
  }, [list])

  return (
    <div
      className="min-h-[100dvh] text-slate-100 p-5 lg:p-6"
      style={{
        background:
          'radial-gradient(ellipse 120% 80% at 50% 0%, #111827 0%, #09090b 50%, #030712 100%)',
      }}
    >
      <header className="mb-5 flex items-end justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-xl font-bold tracking-tight">SOAR Playbooks</h1>
          <p className="text-xs text-white/55 mt-1">
            Build <code className="text-cyan-300">when {`{conditions}`} do [actions]</code> rules
            that fire on every new finding. Live data only.
          </p>
          <p className="text-[10px] font-mono text-white/35 mt-1">{filterSummary}</p>
        </div>
        <div className="flex items-center gap-2">
          <Link
            to="/"
            className="text-[11px] font-mono text-white/45 hover:text-white/80"
          >
            ← Cockpit
          </Link>
          <button
            type="button"
            onClick={startNew}
            className="px-3 py-1.5 rounded border border-cyan-500/40 bg-cyan-500/15 text-cyan-200 text-[12px] font-mono tracking-widest hover:bg-cyan-500/25"
          >
            + New playbook
          </button>
          <button
            type="button"
            onClick={insertExample}
            className="px-3 py-1.5 rounded border border-white/15 text-white/75 text-[12px] font-mono hover:border-cyan-500/30"
          >
            Insert example
          </button>
        </div>
      </header>

      <div className="grid grid-cols-1 xl:grid-cols-[260px_1fr_320px] gap-4">
        {/* ── Left: list of playbooks ──────────────────────────── */}
        <aside className="rounded-2xl border border-white/10 bg-black/35 backdrop-blur-md p-2">
          {loadError && (
            <p className="p-4 text-[11px] font-mono text-rose-300">{loadError}</p>
          )}
          {loading ? (
            <p className="p-4 text-[11px] text-white/45 font-mono">Loading…</p>
          ) : list.length === 0 ? (
            <p className="p-4 text-[11px] text-white/45 font-mono">
              No playbooks yet. Click <strong>+ New playbook</strong> or <strong>Insert example</strong>.
            </p>
          ) : (
            <ul className="space-y-0.5">
              {list.map((pb) => (
                <li key={pb.id}>
                  <button
                    type="button"
                    onClick={() => startEdit(pb)}
                    className={`block w-full text-left px-3 py-2 rounded transition-colors ${
                      selected?.id === pb.id
                        ? 'bg-cyan-500/15 border border-cyan-500/40'
                        : 'border border-transparent hover:bg-white/[0.04]'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 min-w-0">
                      <span className="text-[12px] text-white/85 truncate">{pb.name}</span>
                      <span
                        className={`text-[9px] font-mono uppercase tracking-widest px-1.5 py-0.5 rounded ${
                          pb.enabled
                            ? 'text-emerald-300 bg-emerald-500/10 border border-emerald-500/40'
                            : 'text-white/40 bg-white/[0.04] border border-white/10'
                        }`}
                      >
                        {pb.enabled ? 'on' : 'off'}
                      </span>
                    </div>
                    <div className="text-[10px] font-mono text-white/35 mt-0.5 flex items-center gap-2">
                      <span>{pb.run_count || 0} runs</span>
                      <span className="text-white/15">·</span>
                      <StatusPill status={pb.last_run_status} />
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </aside>

        {/* ── Centre: editor ──────────────────────────────────── */}
        <section className="rounded-2xl border border-white/10 bg-black/35 backdrop-blur-md p-5">
          {!draft ? (
            <p className="text-[11px] text-white/45 font-mono">
              Pick a playbook on the left, or click <strong>+ New playbook</strong>.
            </p>
          ) : (
            <>
              <div className="grid grid-cols-1 md:grid-cols-[1fr_auto] gap-3 mb-4">
                <input
                  type="text"
                  value={draft.name}
                  onChange={(e) => setDraft((d) => ({ ...d, name: e.target.value }))}
                  placeholder="Playbook name"
                  className="bg-black/40 border border-white/15 rounded-lg px-3 py-2 text-[13px] text-white/90 font-medium focus:outline-none focus:border-cyan-500/40"
                />
                <label className="flex items-center gap-2 text-[11px] font-mono text-white/65">
                  <input
                    type="checkbox"
                    checked={!!draft.enabled}
                    onChange={(e) => setDraft((d) => ({ ...d, enabled: e.target.checked }))}
                    className="rounded border-white/30"
                  />
                  Enabled
                </label>
              </div>
              <textarea
                value={draft.description}
                onChange={(e) => setDraft((d) => ({ ...d, description: e.target.value }))}
                placeholder="Description (what this playbook does, who owns it)"
                rows={2}
                className="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2 text-[12px] text-white/75 mb-4 focus:outline-none focus:border-cyan-500/40"
              />

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Trigger */}
                <div>
                  <SectionTitle>When ({`{conditions}`})</SectionTitle>
                  <div className="rounded-xl bg-black/30 border border-white/10 p-3 space-y-3">
                    <div>
                      <p className="text-[10px] font-mono text-white/40 mb-1">Severity (any of)</p>
                      <div className="flex gap-1 flex-wrap">
                        {SEVERITIES.map((s) => {
                          const active = (draft.trigger?.severity || []).includes(s)
                          return (
                            <button
                              type="button"
                              key={s}
                              onClick={() => toggleSev(s)}
                              className={`text-[10px] font-mono uppercase tracking-widest px-2 py-0.5 rounded border ${
                                active
                                  ? 'bg-cyan-500/15 border-cyan-500/40 text-cyan-200'
                                  : 'border-white/10 text-white/45 hover:border-white/30'
                              }`}
                            >
                              {s}
                            </button>
                          )
                        })}
                      </div>
                    </div>
                    <label className="flex items-center gap-2 text-[11px] font-mono text-white/65">
                      <input
                        type="checkbox"
                        checked={!!draft.trigger?.kev}
                        onChange={(e) => updateTrigger({ kev: e.target.checked ? true : undefined })}
                      />
                      Require CISA-KEV listed
                    </label>
                    <label className="flex items-center gap-2 text-[11px] font-mono text-white/65">
                      <input
                        type="checkbox"
                        checked={!!draft.trigger?.exposed}
                        onChange={(e) => updateTrigger({ exposed: e.target.checked ? true : undefined })}
                      />
                      Require internet-exposed asset
                    </label>
                    <label className="block">
                      <span className="text-[10px] font-mono text-white/40">EPSS minimum (0.0–1.0)</span>
                      <input
                        type="number"
                        min="0" max="1" step="0.05"
                        value={draft.trigger?.epss_min ?? ''}
                        onChange={(e) => updateTrigger({
                          epss_min: e.target.value === '' ? undefined : Number(e.target.value),
                        })}
                        className="block w-full mt-1 bg-black/40 border border-white/10 rounded px-2 py-1 text-[12px] text-white/85"
                      />
                    </label>
                    <label className="block">
                      <span className="text-[10px] font-mono text-white/40">Cooldown (seconds)</span>
                      <input
                        type="number"
                        min="0" step="60"
                        value={draft.trigger?.cooldown_seconds ?? ''}
                        onChange={(e) => updateTrigger({
                          cooldown_seconds: e.target.value === '' ? undefined : Number(e.target.value),
                        })}
                        className="block w-full mt-1 bg-black/40 border border-white/10 rounded px-2 py-1 text-[12px] text-white/85"
                      />
                    </label>
                  </div>
                </div>

                {/* Actions */}
                <div>
                  <SectionTitle>Do (actions)</SectionTitle>
                  <div className="rounded-xl bg-black/30 border border-white/10 p-3 space-y-2">
                    <div className="flex gap-1 flex-wrap mb-1">
                      {ACTION_KINDS.map((a) => (
                        <button
                          type="button"
                          key={a.kind}
                          onClick={() => addAction(a.kind)}
                          className="text-[10px] font-mono px-2 py-0.5 rounded border border-white/10 text-white/60 hover:border-cyan-500/30 hover:text-cyan-200"
                        >
                          + {a.label}
                        </button>
                      ))}
                    </div>
                    {(draft.actions || []).length === 0 ? (
                      <p className="text-[11px] font-mono text-white/35 text-center py-3">
                        No actions yet. Add one above.
                      </p>
                    ) : (
                      <ul className="space-y-1.5">
                        {(draft.actions || []).map((a, i) => (
                          <li key={i} className="bg-black/40 border border-white/10 rounded p-2">
                            <div className="flex items-center justify-between gap-2 mb-1">
                              <span className="text-[11px] font-mono text-cyan-200">
                                {i + 1}. {a.kind}
                              </span>
                              <div className="flex items-center gap-1">
                                <button type="button" onClick={() => moveAction(i, -1)} className="text-[10px] text-white/40 hover:text-white/80" title="Move up">↑</button>
                                <button type="button" onClick={() => moveAction(i, +1)} className="text-[10px] text-white/40 hover:text-white/80" title="Move down">↓</button>
                                <button type="button" onClick={() => removeAction(i)} className="text-[10px] text-rose-400 hover:text-rose-300" title="Remove">✕</button>
                              </div>
                            </div>
                            <textarea
                              defaultValue={JSON.stringify(a.params || {}, null, 2)}
                              onBlur={(e) => {
                                try {
                                  const parsed = JSON.parse(e.target.value || '{}')
                                  updateActionParams(i, parsed)
                                } catch (_) {
                                  // leave as-is; user sees the syntax error visually
                                }
                              }}
                              rows={Math.min(8, Math.max(2, JSON.stringify(a.params || {}, null, 2).split('\n').length))}
                              className="w-full bg-black/60 border border-white/10 rounded p-1.5 text-[10px] font-mono text-emerald-300 leading-snug focus:outline-none focus:border-cyan-500/40"
                            />
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                </div>
              </div>

              <div className="mt-4 flex items-center gap-2 flex-wrap">
                <button
                  type="button"
                  onClick={save}
                  disabled={saving}
                  className="px-3 py-1.5 rounded border border-emerald-500/40 bg-emerald-500/15 text-emerald-200 text-[12px] font-mono tracking-widest hover:bg-emerald-500/25 disabled:opacity-50"
                >
                  {saving ? 'Saving…' : selected ? 'Save changes' : 'Create playbook'}
                </button>
                <button
                  type="button"
                  onClick={dryRun}
                  className="px-3 py-1.5 rounded border border-cyan-500/40 text-cyan-200 text-[12px] font-mono tracking-widest hover:bg-cyan-500/15"
                >
                  Dry-run with sample
                </button>
                {selected && (
                  <button
                    type="button"
                    onClick={remove}
                    className="px-3 py-1.5 rounded border border-rose-500/40 text-rose-200 text-[12px] font-mono tracking-widest hover:bg-rose-500/10 ms-auto"
                  >
                    Delete
                  </button>
                )}
                {statusMsg && (
                  <span
                    className={`text-[11px] font-mono ${
                      statusMsg.kind === 'err'
                        ? 'text-rose-300'
                        : statusMsg.kind === 'ok'
                          ? 'text-emerald-300'
                          : 'text-cyan-300'
                    }`}
                  >
                    {statusMsg.text}
                  </span>
                )}
              </div>

              {fireResult && (
                <div className="mt-4 rounded-xl border border-cyan-500/30 bg-cyan-500/5 p-3">
                  <p className="text-[10px] font-mono uppercase tracking-widest text-cyan-300 mb-1">
                    Dry-run result
                  </p>
                  {fireResult.loading ? (
                    <p className="text-[11px] font-mono text-white/55">Firing…</p>
                  ) : (
                    <pre className="text-[10px] font-mono text-white/75 whitespace-pre-wrap overflow-x-auto max-h-60">
                      {JSON.stringify(fireResult.results ?? fireResult, null, 2)}
                    </pre>
                  )}
                </div>
              )}
            </>
          )}
        </section>

        {/* ── Right: run history ───────────────────────────────── */}
        <aside className="rounded-2xl border border-white/10 bg-black/35 backdrop-blur-md p-3">
          <SectionTitle>Run history</SectionTitle>
          {!selected ? (
            <p className="text-[11px] font-mono text-white/35">Select a playbook to see runs.</p>
          ) : runs.length === 0 ? (
            <p className="text-[11px] font-mono text-white/35">No runs yet.</p>
          ) : (
            <ul className="space-y-1.5 max-h-[560px] overflow-y-auto custom-scroll">
              {runs.map((r) => (
                <li key={r.id} className="bg-black/40 border border-white/10 rounded p-2">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[10px] font-mono text-white/60">
                      {r.triggered_at ? new Date(r.triggered_at).toLocaleTimeString() : '—'}
                    </span>
                    <StatusPill status={r.status} />
                  </div>
                  <p className="text-[11px] text-white/85 mt-1">
                    {r.trigger_event?.title || '(no title)'}
                  </p>
                  <p className="text-[10px] font-mono text-white/40">
                    {r.actions_succeeded}/{r.actions_total} ok · {r.actions_failed} failed
                  </p>
                </li>
              ))}
            </ul>
          )}
        </aside>
      </div>
    </div>
  )
}
