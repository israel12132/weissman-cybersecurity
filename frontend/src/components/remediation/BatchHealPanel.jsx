import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Wrench, Loader2, X, CheckCircle, AlertTriangle } from 'lucide-react'
import { apiFetch } from '../../utils/apiFetch'

const CHANNELS = ['github_pr', 'github_direct_commit', 'gitlab_mr', 'bitbucket_pr', 'azure_repos_pr', 'diff_download', 'virtual_patch']

/**
 * BatchHealPanel — heal every fixable finding in a remediation family at once. Groups the findings
 * by client and calls POST /api/clients/:id/heal-batch per client. Repo/token are entered once.
 */
export default function BatchHealPanel({ findings, onClose }) {
  const { t } = useTranslation()
  const [repoSlug, setRepoSlug] = useState('')
  const [gitToken, setGitToken] = useState('')
  const [channel, setChannel] = useState('github_pr')
  const [destructiveConfirm, setDestructiveConfirm] = useState('')
  const [dualApprove, setDualApprove] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  // Only findings that have a generated patch are healable.
  const healable = useMemo(() => findings.filter((f) => f.has_patch && f.client_id && f.finding_id), [findings])

  const byClient = useMemo(() => {
    const m = new Map()
    for (const f of healable) {
      if (!m.has(f.client_id)) m.set(f.client_id, [])
      m.get(f.client_id).push(f.finding_id)
    }
    return m
  }, [healable])

  const submit = async () => {
    if (!repoSlug.trim() || !gitToken.trim()) {
      setError(t('pages.remediationHub.repo_token_required', { defaultValue: 'repo_slug and git_token are required' }))
      return
    }
    setSubmitting(true)
    setError(null)
    setResult(null)
    try {
      const headers = { 'Content-Type': 'application/json' }
      if (destructiveConfirm.trim()) headers['X-Weissman-Destructive-Confirm'] = destructiveConfirm.trim()
      if (dualApprove.trim()) headers['X-Weissman-Dual-Approve'] = dualApprove.trim()
      let enqueued = 0
      let skipped = 0
      for (const [clientId, findingIds] of byClient.entries()) {
        const d = await apiFetch(`/api/clients/${clientId}/heal-batch`, {
          method: 'POST',
          headers,
          body: { finding_ids: findingIds, repo_slug: repoSlug.trim(), git_token: gitToken.trim(), channel },
        })
        enqueued += d.enqueued || 0
        skipped += d.skipped || 0
      }
      setResult({ enqueued, skipped })
    } catch (e) {
      setError(e.message || 'batch heal failed')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="mt-2 p-3 rounded-lg border border-cyan-500/25 bg-cyan-500/[0.04] space-y-2.5">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold text-cyan-200 flex items-center gap-1.5">
          <Wrench className="w-3.5 h-3.5" />
          {t('pages.remediationHub.batch_heal_title', { defaultValue: 'Heal all fixable ({{n}})', n: healable.length })}
        </span>
        <button type="button" onClick={onClose} className="text-white/40 hover:text-white/70"><X className="w-3.5 h-3.5" /></button>
      </div>

      {result ? (
        <div className="text-xs text-emerald-300 flex items-center gap-2">
          <CheckCircle className="w-4 h-4" />
          {t('pages.remediationHub.batch_result', { defaultValue: 'Queued {{enqueued}}, skipped {{skipped}}', enqueued: result.enqueued, skipped: result.skipped })}
        </div>
      ) : (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <input value={repoSlug} onChange={(e) => setRepoSlug(e.target.value)} placeholder="owner/repo"
              className="bg-black/40 border border-white/10 rounded-lg px-2.5 py-1.5 text-xs text-white/85 placeholder-white/25 font-mono focus:outline-none focus:border-cyan-500/40" />
            <input type="password" value={gitToken} onChange={(e) => setGitToken(e.target.value)} placeholder="git token"
              className="bg-black/40 border border-white/10 rounded-lg px-2.5 py-1.5 text-xs text-white/85 placeholder-white/25 font-mono focus:outline-none focus:border-cyan-500/40" />
            <select value={channel} onChange={(e) => setChannel(e.target.value)}
              className="bg-black/40 border border-white/10 rounded-lg px-2.5 py-1.5 text-xs text-white/85 font-mono focus:outline-none focus:border-cyan-500/40">
              {CHANNELS.map((c) => <option key={c} value={c}>{t(`pages.remediationHub.channel_${c === 'github_direct_commit' ? 'github_commit' : c}`, { defaultValue: c })}</option>)}
            </select>
          </div>
          <details className="text-[11px] text-white/45">
            <summary className="cursor-pointer text-white/55">{t('pages.remediationHub.dual_auth_required', { defaultValue: 'Destructive / dual-approval headers (if enforced)' })}</summary>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mt-2">
              <input type="password" value={destructiveConfirm} onChange={(e) => setDestructiveConfirm(e.target.value)} placeholder="X-Weissman-Destructive-Confirm"
                className="bg-black/40 border border-white/10 rounded-lg px-2.5 py-1.5 text-xs text-white/85 font-mono focus:outline-none focus:border-cyan-500/40" />
              <input type="password" value={dualApprove} onChange={(e) => setDualApprove(e.target.value)} placeholder="X-Weissman-Dual-Approve"
                className="bg-black/40 border border-white/10 rounded-lg px-2.5 py-1.5 text-xs text-white/85 font-mono focus:outline-none focus:border-cyan-500/40" />
            </div>
          </details>
          {error && (
            <div className="text-xs text-rose-300 flex items-center gap-2"><AlertTriangle className="w-3.5 h-3.5" /> {error}</div>
          )}
          <button type="button" onClick={submit} disabled={submitting || healable.length === 0}
            className="w-full flex items-center justify-center gap-2 py-2 rounded-lg bg-cyan-500/20 border border-cyan-500/40 text-cyan-200 text-xs font-medium hover:bg-cyan-500/30 disabled:opacity-50">
            {submitting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Wrench className="w-4 h-4" />}
            {t('pages.remediationHub.batch_heal_go', { defaultValue: 'Heal all fixable ({{n}})', n: healable.length })}
          </button>
        </>
      )}
    </div>
  )
}
