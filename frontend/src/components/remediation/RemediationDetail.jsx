import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  X, Wrench, Sparkles, ShieldCheck, AlertTriangle, Download, GitPullRequest,
  Loader2, CheckCircle, XCircle, Languages, ChevronRight, Clock, FileText,
} from 'lucide-react'
import { apiFetch } from '../../utils/apiFetch'
import { apiUrl } from '../../lib/apiBase'

/**
 * RemediationDetail — the "wow" surface. For a single finding it shows a bilingual (he/en)
 * remediation brief (problem, root cause, impact, fix explanation), the before/after diff,
 * a delivery-channel picker with per-channel connect/apply how-to, a one-click Heal action,
 * and the live sandbox-verification timeline with a Fixed / BrokeApp / StillVulnerable verdict.
 */

const CHANNELS = [
  { id: 'github_pr', labelKey: 'channel_github_pr', icon: GitPullRequest, touchesRepo: true },
  { id: 'github_direct_commit', labelKey: 'channel_github_commit', icon: GitPullRequest, touchesRepo: true },
  { id: 'gitlab_mr', labelKey: 'channel_gitlab_mr', icon: GitPullRequest, touchesRepo: true },
  { id: 'bitbucket_pr', labelKey: 'channel_bitbucket_pr', icon: GitPullRequest, touchesRepo: true },
  { id: 'azure_repos_pr', labelKey: 'channel_azure_repos_pr', icon: GitPullRequest, touchesRepo: true },
  { id: 'diff_download', labelKey: 'channel_diff_download', icon: Download, touchesRepo: false },
  { id: 'virtual_patch', labelKey: 'channel_virtual_patch', icon: ShieldCheck, touchesRepo: false },
]

const SEV_COLOR = {
  critical: '#f43f5e', high: '#fb923c', medium: '#fbbf24', low: '#38bdf8', info: '#94a3b8',
}

const VERDICT_META = {
  fixed: { key: 'verdict_fixed', color: '#22c55e', Icon: CheckCircle },
  broke_app: { key: 'verdict_broke_app', color: '#f43f5e', Icon: XCircle },
  still_vulnerable: { key: 'verdict_still_vulnerable', color: '#fb923c', Icon: AlertTriangle },
  inconclusive: { key: 'verdict_inconclusive', color: '#94a3b8', Icon: AlertTriangle },
}

function DiffView({ patch }) {
  if (!patch || !patch.trim()) return null
  const lines = patch.split('\n')
  return (
    <div className="rounded-lg border border-white/10 bg-black/60 overflow-x-auto">
      <pre className="text-[11px] font-mono leading-relaxed p-3 min-w-max">
        {lines.map((ln, i) => {
          let color = 'text-white/55'
          if (ln.startsWith('+') && !ln.startsWith('+++')) color = 'text-green-400'
          else if (ln.startsWith('-') && !ln.startsWith('---')) color = 'text-rose-400'
          else if (ln.startsWith('@@')) color = 'text-cyan-400'
          else if (ln.startsWith('diff ') || ln.startsWith('index ') || ln.startsWith('+++') || ln.startsWith('---')) color = 'text-white/35'
          return <div key={i} className={color}>{ln || ' '}</div>
        })}
      </pre>
    </div>
  )
}

function BilingualBlock({ title, value, mode, curLang }) {
  if (!value || (!value.he && !value.en)) return null
  const showHe = mode === 'both' || curLang === 'he'
  const showEn = mode === 'both' || curLang !== 'he'
  return (
    <div className="space-y-1.5">
      <h4 className="text-xs font-semibold text-cyan-300 uppercase tracking-wide">{title}</h4>
      {showHe && value.he && (
        <p dir="rtl" className="text-sm text-white/85 leading-relaxed text-right">{value.he}</p>
      )}
      {showEn && value.en && (
        <p dir="ltr" className="text-sm text-white/70 leading-relaxed">{value.en}</p>
      )}
    </div>
  )
}

export default function RemediationDetail({ finding, onClose }) {
  const { t, i18n } = useTranslation()
  const curLang = i18n.language?.startsWith('he') ? 'he' : 'en'
  const [langMode, setLangMode] = useState('current') // 'current' | 'both'

  const [brief, setBrief] = useState(finding?.remediation_brief || null)
  const [patch, setPatch] = useState('')
  const [briefLoading, setBriefLoading] = useState(false)
  const [briefError, setBriefError] = useState(null)

  const [channel, setChannel] = useState('github_pr')
  const [repoSlug, setRepoSlug] = useState('')
  const [gitToken, setGitToken] = useState('')
  const [baseBranch, setBaseBranch] = useState('main')
  const [healthCurl, setHealthCurl] = useState('')
  const [destructiveConfirm, setDestructiveConfirm] = useState('')
  const [dualApprove, setDualApprove] = useState('')

  const [healing, setHealing] = useState(false)
  const [healError, setHealError] = useState(null)
  const [reverting, setReverting] = useState(false)
  const [reverted, setReverted] = useState(false)
  const [jobId, setJobId] = useState(null)
  const [steps, setSteps] = useState([])
  const [jobStatus, setJobStatus] = useState(null)
  const [history, setHistory] = useState([])
  const pollRef = useRef(null)

  const clientId = finding?.client_id
  const findingId = finding?.finding_id
  const sev = String(finding?.severity || 'info').toLowerCase()

  const loadBrief = useCallback(async (refresh = false) => {
    if (!clientId || !findingId) return
    setBriefLoading(true)
    setBriefError(null)
    try {
      const q = refresh ? '?refresh=1' : ''
      const d = await apiFetch(`/api/clients/${clientId}/findings/${encodeURIComponent(findingId)}/brief${q}`, {
        method: refresh ? 'POST' : 'GET',
      })
      setBrief(d.brief || null)
      setPatch(d.generated_patch || '')
    } catch (e) {
      setBriefError(e.message || 'failed')
    } finally {
      setBriefLoading(false)
    }
  }, [clientId, findingId])

  // Auto-load the brief on open (uses the cached one if present).
  useEffect(() => { loadBrief(false) }, [loadBrief])

  // Load this finding's heal history (refreshes when a heal completes).
  useEffect(() => {
    if (!clientId || !findingId) return undefined
    let cancelled = false
    apiFetch(`/api/clients/${clientId}/heal-requests`)
      .catch(() => null)
      .then((d) => {
        if (cancelled) return
        const all = Array.isArray(d?.requests) ? d.requests : []
        setHistory(all.filter((x) => x.finding_id === findingId).slice(0, 20))
      })
    return () => { cancelled = true }
  }, [clientId, findingId, jobStatus?.status])

  // Poll verification steps + status while a heal job runs.
  useEffect(() => {
    if (!jobId) return undefined
    let active = true
    const tick = async () => {
      try {
        // Tolerate a per-slot HTTP error (return {} for that call) but RE-THROW a
        // network error (no e.status) so Promise.all rejects into the outer
        // "transient; keep polling" catch — preserving the old behavior where a
        // transient network blip left the last-known status on screen instead of
        // wiping it with td={} for a tick.
        const [sd, td] = await Promise.all([
          apiFetch(`/api/heal-verify/${jobId}/steps`).catch((e) => { if (e?.status) return {}; throw e }),
          apiFetch(`/api/heal-verify/${jobId}`).catch((e) => { if (e?.status) return {}; throw e }),
        ])
        if (!active) return
        if (Array.isArray(sd.steps)) setSteps(sd.steps)
        setJobStatus(td)
        if (td.status === 'completed' || td.status === 'failed') {
          setHealing(false)
          if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null }
        }
      } catch { /* transient; keep polling */ }
    }
    tick()
    pollRef.current = setInterval(tick, 2500)
    return () => { active = false; if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null } }
  }, [jobId])

  const channelHowTo = useMemo(() => {
    const list = brief?.channels || []
    return list.find((c) => c.channel === channel) || null
  }, [brief, channel])

  const selectedChannelMeta = CHANNELS.find((c) => c.id === channel) || CHANNELS[0]

  const runHeal = useCallback(async () => {
    if (!clientId || !findingId) return
    setHealError(null)
    setSteps([])
    setJobStatus(null)
    setJobId(null)
    if (selectedChannelMeta.touchesRepo && (!repoSlug.trim() || !gitToken.trim())) {
      setHealError(t('pages.remediationHub.repo_token_required', { defaultValue: 'repo_slug and git_token are required for this channel' }))
      return
    }
    setHealing(true)
    try {
      const headers = { 'Content-Type': 'application/json' }
      if (destructiveConfirm.trim()) headers['X-Weissman-Destructive-Confirm'] = destructiveConfirm.trim()
      if (dualApprove.trim()) headers['X-Weissman-Dual-Approve'] = dualApprove.trim()
      const d = await apiFetch(`/api/clients/${clientId}/auto-heal`, {
        method: 'POST',
        headers,
        body: {
          finding_id: findingId,
          repo_slug: repoSlug.trim() || undefined,
          git_token: gitToken.trim() || undefined,
          base_branch: baseBranch.trim() || 'main',
          channel,
          health_check_curl: healthCurl.trim() || undefined,
        },
      })
      if (d.job_id) {
        setJobId(d.job_id) // triggers the polling effect
      } else {
        setHealing(false)
        setJobStatus(d)
      }
    } catch (e) {
      setHealing(false)
      setHealError(e.message || 'failed')
    }
  }, [clientId, findingId, repoSlug, gitToken, baseBranch, channel, healthCurl, destructiveConfirm, dualApprove, selectedChannelMeta, t])

  const runRevert = useCallback(async () => {
    if (!clientId || !findingId) return
    if (!repoSlug.trim() || !gitToken.trim()) {
      setHealError(t('pages.remediationHub.repo_token_required', { defaultValue: 'repo_slug and git_token are required' }))
      return
    }
    setReverting(true)
    setHealError(null)
    try {
      const headers = { 'Content-Type': 'application/json' }
      if (destructiveConfirm.trim()) headers['X-Weissman-Destructive-Confirm'] = destructiveConfirm.trim()
      if (dualApprove.trim()) headers['X-Weissman-Dual-Approve'] = dualApprove.trim()
      await apiFetch(`/api/clients/${clientId}/heal-revert`, {
        method: 'POST',
        headers,
        body: {
          finding_id: findingId,
          repo_slug: repoSlug.trim(),
          git_token: gitToken.trim(),
          channel,
          delete_branch: true,
        },
      })
      setReverted(true)
    } catch (e) {
      setHealError(e.message || 'revert failed')
    } finally {
      setReverting(false)
    }
  }, [clientId, findingId, repoSlug, gitToken, channel, destructiveConfirm, dualApprove, t])

  const verdict = jobStatus?.verdict
  const verdictMeta = verdict ? VERDICT_META[verdict] : null

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      {/* eslint-disable-next-line jsx-a11y/no-static-element-interactions, jsx-a11y/click-events-have-key-events -- modal backdrop click-to-dismiss; Escape/close button provide keyboard path */}
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-2xl h-full bg-[#0b0f14] border-l border-white/10 overflow-y-auto shadow-2xl">
        {/* Header */}
        <div className="sticky top-0 z-10 bg-[#0b0f14]/95 backdrop-blur border-b border-white/10 p-4 flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <Wrench className="w-4 h-4 text-cyan-400 shrink-0" />
              <h3 className="text-sm font-semibold text-white truncate">{finding?.title || findingId}</h3>
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase" style={{ color: SEV_COLOR[sev] || SEV_COLOR.info, background: `${SEV_COLOR[sev] || SEV_COLOR.info}18` }}>{sev}</span>
              <span className="text-[10px] font-mono text-white/40">{findingId}</span>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => setLangMode((m) => (m === 'both' ? 'current' : 'both'))}
              className="p-1.5 rounded-md border border-white/10 text-white/60 hover:text-white hover:border-white/25"
              title={t('pages.remediationHub.show_both_languages', { defaultValue: 'Show both languages' })}
            >
              <Languages className="w-4 h-4" />
            </button>
            <button type="button" onClick={onClose} className="p-1.5 rounded-md border border-white/10 text-white/60 hover:text-white hover:border-white/25">
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        <div className="p-4 space-y-6">
          {/* Bilingual brief */}
          <section className="space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-cyan-400" />
                {t('pages.remediationHub.detail_title', { defaultValue: 'Remediation brief' })}
              </h3>
              <button
                type="button"
                onClick={() => loadBrief(true)}
                disabled={briefLoading}
                className="text-xs px-2.5 py-1 rounded-md border border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/10 disabled:opacity-50 flex items-center gap-1.5"
              >
                {briefLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Sparkles className="w-3.5 h-3.5" />}
                {t('pages.remediationHub.generate_brief', { defaultValue: 'Generate brief' })}
              </button>
            </div>

            {briefError && (
              <div className="p-3 rounded-lg border border-rose-500/30 bg-rose-900/20 text-rose-300 text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                {t('pages.remediationHub.brief_error', { defaultValue: 'Could not generate the brief', error: briefError })}: {briefError}
              </div>
            )}

            {briefLoading && !brief && (
              <div className="text-xs text-white/40 flex items-center gap-2"><Loader2 className="w-3.5 h-3.5 animate-spin" /> {t('pages.remediationHub.brief_loading', { defaultValue: 'Generating bilingual brief…' })}</div>
            )}

            {brief && (
              <div className="space-y-4 p-4 rounded-xl border border-white/10 bg-black/30">
                <BilingualBlock title={t('pages.remediationHub.brief_problem', { defaultValue: 'The problem' })} value={brief.problem} mode={langMode} curLang={curLang} />
                <BilingualBlock title={t('pages.remediationHub.brief_root_cause', { defaultValue: 'Root cause' })} value={brief.root_cause} mode={langMode} curLang={curLang} />
                <BilingualBlock title={t('pages.remediationHub.brief_impact', { defaultValue: 'Impact' })} value={brief.impact} mode={langMode} curLang={curLang} />
                <BilingualBlock title={t('pages.remediationHub.brief_fix', { defaultValue: 'The fix' })} value={brief.fix_explanation} mode={langMode} curLang={curLang} />
              </div>
            )}
          </section>

          {/* Before / after diff */}
          {patch && (
            <section className="space-y-2">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <GitPullRequest className="w-4 h-4 text-cyan-400" />
                {t('pages.remediationHub.diff_after', { defaultValue: 'Proposed fix (unified diff)' })}
              </h3>
              <DiffView patch={patch} />
            </section>
          )}

          {/* Channel picker */}
          <section className="space-y-3">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <ChevronRight className="w-4 h-4 text-cyan-400" />
              {t('pages.remediationHub.channel_label', { defaultValue: 'Delivery channel' })}
            </h3>
            <div className="grid grid-cols-2 gap-2">
              {CHANNELS.map((c) => {
                const Icon = c.icon
                const active = channel === c.id
                return (
                  <button
                    key={c.id}
                    type="button"
                    onClick={() => setChannel(c.id)}
                    className={`flex items-center gap-2 p-2.5 rounded-lg border text-xs text-left transition-colors ${active ? 'border-cyan-500/50 bg-cyan-500/10 text-cyan-200' : 'border-white/10 text-white/60 hover:border-white/25'}`}
                  >
                    <Icon className="w-4 h-4 shrink-0" />
                    <span>{t(`pages.remediationHub.${c.labelKey}`, { defaultValue: c.id })}</span>
                  </button>
                )
              })}
            </div>

            {channelHowTo && (
              <div className="space-y-3 p-3 rounded-lg border border-white/10 bg-black/30">
                <BilingualBlock title={t('pages.remediationHub.channel_connect', { defaultValue: 'How to connect' })} value={channelHowTo.connect} mode={langMode} curLang={curLang} />
                <BilingualBlock title={t('pages.remediationHub.channel_apply', { defaultValue: 'How to apply' })} value={channelHowTo.apply} mode={langMode} curLang={curLang} />
              </div>
            )}
          </section>

          {/* Heal form */}
          <section className="space-y-3">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-cyan-400" />
              {t('pages.remediationHub.heal_now', { defaultValue: 'Heal now' })}
            </h3>
            {selectedChannelMeta.touchesRepo ? (
              <div className="grid grid-cols-1 gap-2">
                <Field label={t('pages.remediationHub.repo_slug', { defaultValue: 'Repository (owner/repo)' })} value={repoSlug} onChange={setRepoSlug} placeholder="owner/repo" />
                <Field label={t('pages.remediationHub.git_token', { defaultValue: 'GitHub token (repo scope)' })} value={gitToken} onChange={setGitToken} type="password" placeholder="ghp_…" />
                <Field label={t('pages.remediationHub.base_branch', { defaultValue: 'Base branch' })} value={baseBranch} onChange={setBaseBranch} placeholder="main" />
              </div>
            ) : (
              <div className="grid grid-cols-1 gap-2">
                <p className="text-[11px] text-white/45">{t('pages.remediationHub.channel_no_repo', { defaultValue: 'This channel does not modify your repository. Sandbox verification still needs read access below.' })}</p>
                <Field label={t('pages.remediationHub.repo_slug', { defaultValue: 'Repository (owner/repo)' })} value={repoSlug} onChange={setRepoSlug} placeholder="owner/repo" />
                <Field label={t('pages.remediationHub.git_token', { defaultValue: 'GitHub token (repo scope)' })} value={gitToken} onChange={setGitToken} type="password" placeholder="ghp_…" />
              </div>
            )}
            <Field label={t('pages.remediationHub.health_curl', { defaultValue: 'Health check curl (optional)' })} value={healthCurl} onChange={setHealthCurl} placeholder="curl http://localhost:3000/health" />
            <details className="text-[11px] text-white/50">
              <summary className="cursor-pointer text-white/60">{t('pages.remediationHub.dual_auth_required', { defaultValue: 'Destructive / dual-approval headers (if enforced)' })}</summary>
              <div className="grid grid-cols-1 gap-2 mt-2">
                <Field label="X-Weissman-Destructive-Confirm" value={destructiveConfirm} onChange={setDestructiveConfirm} type="password" />
                <Field label="X-Weissman-Dual-Approve" value={dualApprove} onChange={setDualApprove} type="password" />
                <p className="text-white/35">{t('pages.remediationHub.dual_auth_hint', { defaultValue: 'Required only when the server sets the corresponding secrets (production). Requires admin role.' })}</p>
              </div>
            </details>

            {healError && (
              <div className="p-3 rounded-lg border border-rose-500/30 bg-rose-900/20 text-rose-300 text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0" /> {healError}
              </div>
            )}

            <button
              type="button"
              onClick={runHeal}
              disabled={healing}
              className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg bg-cyan-500/20 border border-cyan-500/40 text-cyan-200 font-medium hover:bg-cyan-500/30 disabled:opacity-50"
            >
              {healing ? <Loader2 className="w-4 h-4 animate-spin" /> : <Wrench className="w-4 h-4" />}
              {healing ? t('pages.remediationHub.healing', { defaultValue: 'Healing…' }) : t('pages.remediationHub.heal_now', { defaultValue: 'Heal now' })}
            </button>
          </section>

          {/* Live verification timeline + verdict */}
          {(steps.length > 0 || jobStatus) && (
            <section className="space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-cyan-400" />
                  {t('pages.remediationHub.verification_steps', { defaultValue: 'Sandbox verification' })}
                </h3>
                <div className="flex items-center gap-2 flex-wrap">
                  {jobStatus?.attempts > 1 && (
                    <span className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-[10px] font-mono text-amber-300 bg-amber-500/10 border border-amber-500/25">
                      {t('pages.remediationHub.self_repair_attempts', { defaultValue: 'self-repair ×{{n}}', n: jobStatus.attempts })}
                    </span>
                  )}
                  {jobStatus?.attested && (
                    <a
                      href={apiUrl(`/api/heal-verify/${jobId}/attestation`)}
                      target="_blank"
                      rel="noreferrer"
                      title={t('pages.remediationHub.verify_attestation', { defaultValue: 'Verify signed receipt' })}
                      className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-[10px] font-mono text-emerald-300 bg-emerald-500/10 border border-emerald-500/25 hover:bg-emerald-500/20"
                    >
                      🔏 {t('pages.remediationHub.attested', { defaultValue: 'attested' })}
                    </a>
                  )}
                  {verdictMeta && (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium" style={{ color: verdictMeta.color, background: `${verdictMeta.color}18`, border: `1px solid ${verdictMeta.color}44` }}>
                      <verdictMeta.Icon className="w-3.5 h-3.5" />
                      {t(`pages.remediationHub.${verdictMeta.key}`, { defaultValue: verdict })}
                    </span>
                  )}
                </div>
              </div>

              {jobStatus?.pr_url && (
                <div className="flex items-center gap-3 flex-wrap">
                  <a href={jobStatus.pr_url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-xs text-cyan-300 hover:text-cyan-200">
                    <GitPullRequest className="w-3.5 h-3.5" /> {t('pages.remediationHub.view_pr', { defaultValue: 'View pull request' })}
                  </a>
                  {reverted ? (
                    <span className="inline-flex items-center gap-1 text-xs text-white/40">
                      <X className="w-3.5 h-3.5" /> {t('pages.remediationHub.reverted', { defaultValue: 'reverted' })}
                    </span>
                  ) : (
                    <button
                      type="button"
                      onClick={runRevert}
                      disabled={reverting}
                      className="inline-flex items-center gap-1.5 text-xs text-rose-300/80 hover:text-rose-200 disabled:opacity-50"
                      title={t('pages.remediationHub.revert_hint', { defaultValue: 'Close the auto-opened PR/MR' })}
                    >
                      {reverting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <X className="w-3.5 h-3.5" />}
                      {t('pages.remediationHub.revert', { defaultValue: 'Revert' })}
                    </button>
                  )}
                </div>
              )}
              <div className="flex items-center gap-4 flex-wrap">
                {jobId && (jobStatus?.channel === 'diff_download' || jobStatus?.channel === 'virtual_patch') && jobStatus?.status === 'completed' && (
                  <a href={apiUrl(`/api/heal-verify/${jobId}/patch`)} className="inline-flex items-center gap-1.5 text-xs text-cyan-300 hover:text-cyan-200">
                    <Download className="w-3.5 h-3.5" /> {t('pages.remediationHub.download_patch', { defaultValue: 'Download patch' })}
                  </a>
                )}
                {jobId && jobStatus?.status === 'completed' && (
                  <a href={apiUrl(`/api/heal-verify/${jobId}/report`)} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-xs text-cyan-300 hover:text-cyan-200" title={t('pages.remediationHub.report_hint', { defaultValue: 'Open a printable bilingual remediation report' })}>
                    <FileText className="w-3.5 h-3.5" /> {t('pages.remediationHub.download_report', { defaultValue: 'Remediation report' })}
                  </a>
                )}
                {jobId && jobStatus?.status === 'completed' && (
                  <a href={apiUrl(`/api/heal-verify/${jobId}/report.json`)} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-xs text-white/50 hover:text-white/80" title={t('pages.remediationHub.report_json_hint', { defaultValue: 'Machine-readable JSON (weissman-heal-report/v1)' })}>
                    <FileText className="w-3.5 h-3.5" /> JSON
                  </a>
                )}
                {jobId && jobStatus?.status === 'completed' && (
                  <a href={apiUrl(`/api/heal-verify/${jobId}/sarif`)} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-xs text-white/50 hover:text-white/80" title={t('pages.remediationHub.report_sarif_hint', { defaultValue: 'SARIF 2.1.0 for GitHub code scanning / SAST' })}>
                    <FileText className="w-3.5 h-3.5" /> SARIF
                  </a>
                )}
              </div>

              <ol className="space-y-1.5 border-l border-white/10 pl-4">
                {steps.map((s, i) => (
                  <li key={i} className="text-xs">
                    <span className="font-mono text-cyan-300">{s.step}</span>
                    {s.detail && <span className="text-white/50"> — {s.detail}</span>}
                  </li>
                ))}
                {healing && steps.length === 0 && (
                  <li className="text-xs text-white/40 flex items-center gap-2"><Loader2 className="w-3.5 h-3.5 animate-spin" /> {t('pages.remediationHub.step_waiting', { defaultValue: 'Waiting for the worker…' })}</li>
                )}
              </ol>
            </section>
          )}

          {/* Heal history for this finding */}
          {history.length > 0 && (
            <section className="space-y-2">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Clock className="w-4 h-4 text-cyan-400" />
                {t('pages.remediationHub.heal_history', { defaultValue: 'Heal history' })}
              </h3>
              <div className="divide-y divide-white/5 rounded-lg border border-white/10 overflow-hidden">
                {history.map((h) => {
                  const vm = h.verdict ? VERDICT_META[h.verdict] : null
                  return (
                    <div key={h.id} className="flex items-center justify-between gap-2 px-3 py-2 text-xs">
                      <div className="flex items-center gap-2 min-w-0">
                        {vm ? (
                          <span style={{ color: vm.color }}>●</span>
                        ) : (
                          <span className="text-white/30">●</span>
                        )}
                        <span className="text-white/70 truncate">{h.verification_status || h.verdict || '—'}</span>
                        {h.channel && <span className="text-[10px] text-white/35 font-mono">{h.channel}</span>}
                        {h.attempts > 1 && <span className="text-[10px] text-amber-300/70 font-mono">×{h.attempts}</span>}
                        {h.attested && <span className="text-[10px] text-emerald-300/70">🔏</span>}
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        {h.pr_url && (
                          <a href={h.pr_url} target="_blank" rel="noreferrer" className="text-cyan-300/80 hover:text-cyan-200">
                            <GitPullRequest className="w-3.5 h-3.5" />
                          </a>
                        )}
                        <span className="text-[10px] text-white/30 font-mono whitespace-nowrap">{(h.created_at || '').slice(0, 10)}</span>
                      </div>
                    </div>
                  )
                })}
              </div>
            </section>
          )}
        </div>
      </div>
    </div>
  )
}

function Field({ label, value, onChange, type = 'text', placeholder = '' }) {
  return (
    <label className="block">
      <span className="text-[11px] text-white/50 font-mono">{label}</span>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="mt-1 w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2 text-xs text-white/85 placeholder-white/25 font-mono focus:outline-none focus:border-cyan-500/40"
      />
    </label>
  )
}
