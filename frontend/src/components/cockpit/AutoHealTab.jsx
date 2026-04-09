/**
 * CNAPP Layer 3–4: Auto-Heal with 200% Docker verification — live sandbox steps, then PR.
 */
import React, { useCallback, useEffect, useRef, useState } from 'react'
import { useClient } from '../../context/ClientContext'
import { destructiveHeaders } from '../../utils/destructiveConfirm'
import { Shield, GitPullRequest, CheckCircle, Clock, ExternalLink, Loader2, Container } from 'lucide-react'
import { apiFetch } from '../../lib/apiBase'

function terminalStep(s) {
  if (s === 'verified') return 'ok'
  if (s === 'failed') return 'fail'
  if (s?.includes('exploit')) return 'exploit'
  return 'run'
}

export default function AutoHealTab() {
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
        Select a client to use Auto-Heal.
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <Shield className="w-5 h-5 text-[#10b981]" />
        <h2 className="text-lg font-semibold text-white">1-Click Auto-Heal</h2>
      </div>

      <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-4">
        <h3 className="text-sm font-medium text-white/90 mb-3">Create remediation PR (200% Docker verify first)</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <input
            type="text"
            placeholder="Finding ID"
            value={healForm.finding_id}
            onChange={e => setHealForm(f => ({ ...f, finding_id: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white placeholder-white/40 text-sm"
          />
          <input
            type="text"
            placeholder="Repo (owner/repo)"
            value={healForm.repo_slug}
            onChange={e => setHealForm(f => ({ ...f, repo_slug: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white placeholder-white/40 text-sm"
          />
          <input
            type="password"
            placeholder="Git token"
            value={healForm.git_token}
            onChange={e => setHealForm(f => ({ ...f, git_token: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white placeholder-white/40 text-sm"
          />
          <input
            type="text"
            placeholder="Base branch"
            value={healForm.base_branch}
            onChange={e => setHealForm(f => ({ ...f, base_branch: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white placeholder-white/40 text-sm"
          />
          <div className="md:col-span-2 flex items-center gap-2 text-white/50 text-xs">
            <Container className="w-4 h-4 shrink-0" />
            <span>Ephemeral sandbox (bollard / Docker API)</span>
          </div>
          <input
            type="text"
            placeholder="Docker socket"
            value={healForm.docker_socket}
            onChange={e => setHealForm(f => ({ ...f, docker_socket: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white placeholder-white/40 text-sm font-mono text-xs"
          />
          <input
            type="text"
            placeholder="Image (e.g. node:20-bookworm)"
            value={healForm.image}
            onChange={e => setHealForm(f => ({ ...f, image: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white placeholder-white/40 text-sm"
          />
          <input
            type="text"
            placeholder="Container app port"
            value={healForm.container_port}
            onChange={e => setHealForm(f => ({ ...f, container_port: e.target.value }))}
            className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 text-white placeholder-white/40 text-sm"
          />
        </div>
        <p className="mt-2 text-[10px] text-white/40">
          Set <code className="text-[#22d3ee]">WEISSMAN_AUTOHEAL_SKIP_SANDBOX=1</code> on the engine to open PRs without Docker (not recommended).
        </p>
        <button
          type="button"
          onClick={triggerHeal}
          disabled={healing != null}
          className="mt-3 flex items-center gap-2 px-4 py-2 rounded-xl border border-[#10b981]/50 bg-[#10b981]/10 text-[#10b981] hover:bg-[#10b981]/20 disabled:opacity-50"
        >
          {healing ? <Loader2 className="w-4 h-4 animate-spin" /> : <GitPullRequest className="w-4 h-4" />}
          {healing ? 'Starting…' : 'Verify in sandbox & open PR'}
        </button>
      </div>

      {(verifyJobId || verifySteps.length > 0) && (
        <div className="rounded-2xl bg-black/50 border border-[#22d3ee]/30 p-4">
          <div className="flex items-center justify-between mb-3">
            <span className="text-sm font-medium text-[#22d3ee]">Sandbox verification (live)</span>
            {verifyJobId && (
              <span className="text-[10px] font-mono text-white/40 truncate max-w-[200px]" title={verifyJobId}>
                job {verifyJobId.slice(0, 8)}…
              </span>
            )}
          </div>
          <ul className="space-y-2 max-h-64 overflow-y-auto">
            {verifySteps.length === 0 && (
              <li className="text-xs text-white/50 flex items-center gap-2">
                <Loader2 className="w-3 h-3 animate-spin" /> Waiting for engine steps…
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
          <span className="text-sm font-medium text-white/90">Heal requests</span>
          <button type="button" onClick={fetchRequests} className="text-xs text-[#22d3ee] hover:underline">
            Refresh
          </button>
        </div>
        {loading ? (
          <div className="p-6 text-center text-white/50 text-sm">Loading…</div>
        ) : requests.length === 0 ? (
          <div className="p-6 text-center text-white/50 text-sm">No heal requests yet. Trigger one above.</div>
        ) : (
          <ul className="divide-y divide-white/10">
            {requests.map(req => (
              <li key={req.id} className="p-4 hover:bg-white/5">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-white font-mono text-sm">{req.finding_id}</span>
                  {String(req.verification_status || '').includes('verified') && (
                    <CheckCircle className="w-4 h-4 text-[#10b981]" />
                  )}
                  {String(req.verification_status || '').includes('sandbox_failed') ||
                  String(req.verification_status || '').includes('pr_failed') ? (
                    <Clock className="w-4 h-4 text-red-400" />
                  ) : null}
                  {!String(req.verification_status || '').includes('verified') &&
                    !String(req.verification_status || '').includes('failed') &&
                    !String(req.verification_status || '').includes('pr_failed') && (
                      <Clock className="w-4 h-4 text-amber-400" />
                    )}
                </div>
                {req.verification_job_id ? (
                  <div className="mt-1 text-[10px] text-white/40 font-mono">verify job: {req.verification_job_id}</div>
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
                    Open PR / Approve & merge
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
