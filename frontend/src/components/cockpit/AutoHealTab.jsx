/**
 * CNAPP Layer 3–4: Auto-Heal with 200% Docker verification — live sandbox steps, then PR.
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useClient } from '../../context/ClientContext'
import { destructiveHeaders } from '../../utils/destructiveConfirm'
import { Shield, GitPullRequest, CheckCircle, Clock, ExternalLink, Loader2, Container } from 'lucide-react'
import { apiFetch } from '../../lib/apiBase'

const NS = 'components.cockpitTabs.autoHeal'

function terminalStep(s) {
  if (s === 'verified') return 'ok'
  if (s === 'failed') return 'fail'
  if (s?.includes('exploit')) return 'exploit'
  return 'run'
}

export default function AutoHealTab() {
  const { t } = useTranslation()
  const { selectedClientId } = useClient()
  const [requests, setRequests] = useState([])
  const [loading, setLoading] = useState(false)
  const [healing, setHealing] = useState(null)
  const [verifyJobId, setVerifyJobId] = useState(null)
  const [verifySteps, setVerifySteps] = useState([])
  const pollRef = useRef(null)
  const [healForm, setHealForm] = useState({
    finding_id: '',
    git_token: '',
    repo_slug: '',
    base_branch: 'main',
    docker_socket: '/var/run/docker.sock',
    image: 'node:20-bookworm',
    container_port: '3000',
  })

  const fetchRequests = useCallback(async () => {
    if (!selectedClientId) {
      setRequests([])
      return
    }
    setLoading(true)
    try {
      const r = await apiFetch(`/api/clients/${selectedClientId}/heal-requests`)
      if (r.ok) {
        const d = await r.json()
        const list = Array.isArray(d) ? d : (d.requests ?? [])
        setRequests(list)
      }
    } catch (_) {
      setRequests([])
    } finally {
      setLoading(false)
    }
  }, [selectedClientId])

  useEffect(() => {
    fetchRequests()
  }, [fetchRequests])

  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current)
    }
  }, [])

  const stopPoll = () => {
    if (pollRef.current) {
      clearInterval(pollRef.current)
      pollRef.current = null
    }
  }

  const startVerifyPoll = (jobId) => {
    stopPoll()
    setVerifyJobId(jobId)
    setVerifySteps([])
    const tick = async () => {
      try {
        const r = await apiFetch(`/api/heal-verify/${encodeURIComponent(jobId)}/steps`)
        if (!r.ok) {
          stopPoll()
          setVerifyJobId(null)
          await fetchRequests()
          return
        }
        const d = await r.json()
        const steps = d.steps || []
        setVerifySteps(steps)
        const last = steps[steps.length - 1]
        if (last && (last.step === 'verified' || last.step === 'failed')) {
          stopPoll()
          setVerifyJobId(null)
          await fetchRequests()
        }
      } catch (_) {
        stopPoll()
        setVerifyJobId(null)
        await fetchRequests()
      }
    }
    tick()
    pollRef.current = setInterval(tick, 1200)
  }

  const triggerHeal = async () => {
    if (!selectedClientId || !healForm.finding_id.trim()) return
    setHealing(healForm.finding_id)
    stopPoll()
    setVerifySteps([])
    setVerifyJobId(null)
    try {
      const port = parseInt(healForm.container_port, 10)
      const body = {
        finding_id: healForm.finding_id.trim(),
        git_token: healForm.git_token || undefined,
        repo_slug: healForm.repo_slug || undefined,
        base_branch: healForm.base_branch || 'main',
        docker_socket: healForm.docker_socket || undefined,
        image: healForm.image || undefined,
        container_port: Number.isFinite(port) ? port : undefined,
      }
      const res = await apiFetch(`/api/clients/${selectedClientId}/auto-heal`, {
        method: 'POST',
        headers: destructiveHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(body),
      })
      const data = await res.json().catch(() => ({}))
      if (res.status === 202 && data.job_id) {
        startVerifyPoll(data.job_id)
      } else {
        await fetchRequests()
      }
    } catch (_) {}
    setHealing(null)
  }

  if (!selectedClientId) {
    return (
      <div className="p-8 rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 text-center text-white/70">
        {t(`${NS}.selectClient`)}
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <Shield className="w-5 h-5 text-[#10b981]" />
        <h2 className="text-lg font-semibold text-white">{t(`${NS}.title`)}</h2>
      </div>

      <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-4">
        <h3 className="text-sm font-medium text-white/90 mb-3">{t(`${NS}.formTitle`)}</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <input
            type="text"
            placeholder={t(`${NS}.findingId`)}
            value={healForm.finding_id}
            onChange={e => setHealForm(f => ({ ...f, finding_id: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white placeholder-white/40 text-sm"
          />
          <input
            type="text"
            placeholder={t(`${NS}.repoSlug`)}
            value={healForm.repo_slug}
            onChange={e => setHealForm(f => ({ ...f, repo_slug: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white placeholder-white/40 text-sm"
          />
          <input
            type="password"
            placeholder={t(`${NS}.gitToken`)}
            value={healForm.git_token}
            onChange={e => setHealForm(f => ({ ...f, git_token: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white placeholder-white/40 text-sm"
          />
          <input
            type="text"
            placeholder={t(`${NS}.baseBranch`)}
            value={healForm.base_branch}
            onChange={e => setHealForm(f => ({ ...f, base_branch: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white placeholder-white/40 text-sm"
          />
          <div className="md:col-span-2 flex items-center gap-2 text-white/50 text-xs">
            <Container className="w-4 h-4 shrink-0" />
            <span>{t(`${NS}.ephemeralSandbox`)}</span>
          </div>
          <input
            type="text"
            placeholder={t(`${NS}.dockerSocket`)}
            value={healForm.docker_socket}
            onChange={e => setHealForm(f => ({ ...f, docker_socket: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white placeholder-white/40 text-sm font-mono text-xs"
          />
          <input
            type="text"
            placeholder={t(`${NS}.image`)}
            value={healForm.image}
            onChange={e => setHealForm(f => ({ ...f, image: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white placeholder-white/40 text-sm"
          />
          <input
            type="text"
            placeholder={t(`${NS}.containerPort`)}
            value={healForm.container_port}
            onChange={e => setHealForm(f => ({ ...f, container_port: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white placeholder-white/40 text-sm"
          />
        </div>
        <p className="mt-2 text-[10px] text-white/40">
          {t(`${NS}.skipSandboxHint`)}
        </p>
        <button
          type="button"
          onClick={triggerHeal}
          disabled={healing != null}
          className="mt-3 flex items-center gap-2 px-4 py-2 rounded-xl border border-[#10b981]/50 bg-[#10b981]/10 text-[#10b981] hover:bg-[#10b981]/20 disabled:opacity-50"
        >
          {healing ? <Loader2 className="w-4 h-4 animate-spin" /> : <GitPullRequest className="w-4 h-4" />}
          {healing ? t(`${NS}.starting`) : t(`${NS}.verifyButton`)}
        </button>
      </div>

      {(verifyJobId || verifySteps.length > 0) && (
        <div className="rounded-2xl bg-black/50 border border-[#22d3ee]/30 p-4">
          <div className="flex items-center justify-between mb-3">
            <span className="text-sm font-medium text-[#22d3ee]">{t(`${NS}.sandboxVerificationLive`)}</span>
            {verifyJobId && (
              <span className="text-[10px] font-mono text-white/40 truncate max-w-[200px]" title={verifyJobId}>
                {t(`${NS}.jobPrefix`, { id: verifyJobId.slice(0, 8) })}
              </span>
            )}
          </div>
          <ul className="space-y-2 max-h-64 overflow-y-auto">
            {verifySteps.length === 0 && (
              <li className="text-xs text-white/50 flex items-center gap-2">
                <Loader2 className="w-3 h-3 animate-spin" /> {t(`${NS}.waitingSteps`)}
              </li>
            )}
            {verifySteps.map((st, i) => (
              <li
                key={`${st.ts}-${i}`}
                className={`text-xs rounded-lg px-3 py-2 border ${
                  terminalStep(st.step) === 'ok'
                    ? 'border-[#10b981]/40 bg-[#10b981]/5'
                    : terminalStep(st.step) === 'fail'
                      ? 'border-red-500/40 bg-red-500/5'
                      : 'border-white/10 bg-black/40'
                }`}
              >
                <div className="font-mono text-[#a5f3fc]">{st.step}</div>
                {st.detail && <div className="mt-1 text-white/60 break-all">{st.detail}</div>}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 overflow-hidden">
        <div className="px-4 py-3 border-b border-white/10 flex items-center justify-between">
          <span className="text-sm font-medium text-white/90">{t(`${NS}.healRequests`)}</span>
          <button type="button" onClick={fetchRequests} className="text-xs text-[#22d3ee] hover:underline">
            {t(`${NS}.refresh`)}
          </button>
        </div>
        {loading ? (
          <div className="p-6 text-center text-white/50 text-sm">{t(`${NS}.loading`)}</div>
        ) : requests.length === 0 ? (
          <div className="p-6 text-center text-white/50 text-sm">{t(`${NS}.noRequests`)}</div>
        ) : (
          <ul className="divide-y divide-white/10">
            {requests.map(req => (
              <li key={req.id} className="p-4 hover:bg-white/5">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-white font-mono text-sm">{req.finding_id}</span>
                  {String(req.verification_status || '').includes('verified') && (
                    <CheckCircle className="w-4 h-4 text-[#10b981]" />
                  )}
                  {String(req.verification_status || '').includes('failed') ? (
                    <Clock className="w-4 h-4 text-red-400" />
                  ) : null}
                  {!String(req.verification_status || '').includes('verified') &&
                    !String(req.verification_status || '').includes('failed') &&
                    !String(req.verification_status || '').includes('pr_failed') && (
                      <Clock className="w-4 h-4 text-amber-400" />
                    )}
                </div>
                {req.verification_job_id ? (
                  <div className="mt-1 text-[10px] text-white/40 font-mono">
                    {t(`${NS}.verifyJobPrefix`, { id: req.verification_job_id })}
                  </div>
                ) : null}
                {req.diff_summary && (
                  <pre className="mt-2 p-2 rounded-lg bg-black/60 border border-white/10 text-[10px] text-[#4ade80] font-mono overflow-x-auto max-h-24 overflow-y-auto">
                    {req.diff_summary}
                  </pre>
                )}
                <div className="mt-1 text-[10px] text-white/50">{req.verification_status}</div>
                {req.pr_url && (
                  <a
                    href={req.pr_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 mt-2 text-xs text-[#22d3ee] hover:underline"
                  >
                    <ExternalLink className="w-3 h-3" />
                    {t(`${NS}.openPr`)}
                  </a>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}
