import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { FlaskConical, Loader2 } from 'lucide-react'
import { apiFetch } from '../../utils/apiFetch'
import Button from '../ui/Button'
import ProofStatusBadge, { proofStatusOf } from './ProofStatusBadge'
import { findingVerifyId } from './FindingLiveVerify'

function isAbortError(err) {
  return err?.name === 'AbortError' || /aborted|abort|timeout/i.test(String(err?.message || ''))
}

function artifactHref(item) {
  const ev = item?.evidence && typeof item.evidence === 'object' ? item.evidence : {}
  const ref = ev.ref || ev.screenshot_ref || ev.screenshot_url || ev.url
  if (typeof ref === 'string' && /^https?:\/\//i.test(ref)) return ref
  if (item?.campaign_id) {
    return `/command-center/campaigns`
  }
  return ''
}

export default function FindingSafeProof({ finding, onProofComplete }) {
  const { t } = useTranslation()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [artifacts, setArtifacts] = useState([])
  const [reason, setReason] = useState('')

  const rawId = useMemo(() => findingVerifyId(finding), [finding])
  const status = proofStatusOf(finding)

  const loadArtifacts = useCallback(async () => {
    if (!rawId || !/^\d+$/.test(rawId)) {
      setArtifacts([])
      return
    }
    try {
      const d = await apiFetch(`/api/findings/${encodeURIComponent(rawId)}/proof`)
      if (d?.ok === false) return
      setArtifacts(Array.isArray(d?.artifacts) ? d.artifacts : [])
      if (d?.reason) setReason(String(d.reason))
    } catch {
      setArtifacts([])
    }
  }, [rawId])

  useEffect(() => {
    loadArtifacts()
  }, [loadArtifacts, finding?.proof_status])

  const runProof = useCallback(async (e) => {
    e?.stopPropagation?.()
    e?.preventDefault?.()
    if (loading) return
    if (!rawId) {
      setError(t('findings.proof.missing_id'))
      return
    }
    setLoading(true)
    setError('')
    const controller = typeof AbortController !== 'undefined' ? new AbortController() : null
    const timer = controller ? setTimeout(() => controller.abort(), 45_000) : null
    try {
      const d = await apiFetch(`/api/findings/${encodeURIComponent(rawId)}/proof`, {
        method: 'POST',
        body: { live: true },
        signal: controller?.signal,
        breaker: false,
      })
      if (!d || d.ok === false) {
        throw new Error(d?.detail || d?.error || t('findings.proof.failed'))
      }
      if (d.invented) {
        throw new Error(t('findings.proof.failed'))
      }
      setReason(d.reason ? String(d.reason) : '')
      if (Array.isArray(d.artifacts) && d.artifacts.length) {
        setArtifacts(d.artifacts)
      } else {
        await loadArtifacts()
      }
      onProofComplete?.(rawId, d)
    } catch (err) {
      if (isAbortError(err)) {
        setError(t('findings.proof.timeout'))
      } else {
        setError(err?.message || t('findings.proof.failed'))
      }
    } finally {
      if (timer) clearTimeout(timer)
      setLoading(false)
    }
  }, [rawId, loading, onProofComplete, t, loadArtifacts])

  return (
    <div className="space-y-3" data-testid="finding-safe-proof">
      <div className="flex flex-wrap items-center gap-2">
        <ProofStatusBadge status={status} />
        <Button
          variant="unstyled"
          type="button"
          onClick={runProof}
          disabled={loading || !rawId}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-mono border border-emerald-500/35 bg-emerald-500/10 text-emerald-200 hover:bg-emerald-500/20 disabled:opacity-40"
        >
          {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <FlaskConical className="w-3.5 h-3.5" />}
          {loading ? t('findings.proof.running') : t('findings.proof.run')}
        </Button>
      </div>
      {error && (
        <p className="text-[11px] font-mono text-rose-300" role="alert">{error}</p>
      )}
      {reason && (
        <p className="text-[12px] text-[var(--text-secondary)]">{reason}</p>
      )}
      {artifacts.length === 0 ? (
        <p className="text-[12px] text-[var(--text-muted)]">{t('findings.proof.no_artifacts')}</p>
      ) : (
        <ul className="space-y-2">
          {artifacts.map((item, i) => {
            const href = artifactHref(item)
            const key = item.id != null ? String(item.id) : `art-${i}`
            return (
              <li
                key={key}
                className="rounded-lg border border-[var(--border-default)] bg-[var(--bg-3)] px-3 py-2"
              >
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <span className="text-[11px] font-mono text-emerald-300/90">
                    {item.adapter || 'classifier'} · {item.kind || 'engine_output'}
                  </span>
                  {href && (
                    <a
                      href={href}
                      target={href.startsWith('http') ? '_blank' : undefined}
                      rel={href.startsWith('http') ? 'noopener noreferrer' : undefined}
                      className="text-[10px] font-mono text-cyan-300 hover:underline"
                    >
                      {t('findings.proof.link_evidence')}
                    </a>
                  )}
                </div>
                {item.evidence != null && (
                  <pre className="mt-1 text-[10px] font-mono text-[var(--text-tertiary)] overflow-x-auto max-h-32 whitespace-pre-wrap break-all m-0">
                    {typeof item.evidence === 'string' ? item.evidence : JSON.stringify(item.evidence)}
                  </pre>
                )}
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}

export function FindingSafeProofButton({ finding, onProofComplete }) {
  const { t } = useTranslation()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const rawId = useMemo(() => findingVerifyId(finding), [finding])

  const runProof = useCallback(async (e) => {
    e?.stopPropagation?.()
    e?.preventDefault?.()
    if (loading || !rawId) return
    setLoading(true)
    setError('')
    try {
      const d = await apiFetch(`/api/findings/${encodeURIComponent(rawId)}/proof`, {
        method: 'POST',
        body: { live: true },
        breaker: false,
      })
      if (!d || d.ok === false) {
        throw new Error(d?.detail || t('findings.proof.failed'))
      }
      onProofComplete?.(rawId, d)
    } catch (err) {
      setError(err?.message || t('findings.proof.failed'))
    } finally {
      setLoading(false)
    }
  }, [rawId, loading, onProofComplete, t])

  return (
    <span className="inline-flex flex-col items-start gap-1">
      <Button
        variant="unstyled"
        type="button"
        onClick={runProof}
        disabled={loading || !rawId}
        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-mono border border-emerald-500/35 bg-emerald-500/10 text-emerald-200 hover:bg-emerald-500/20 disabled:opacity-40"
      >
        {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <FlaskConical className="w-3.5 h-3.5" />}
        {loading ? t('findings.proof.running') : t('findings.proof.run')}
      </Button>
      {error && <span className="text-[10px] font-mono text-rose-300">{error}</span>}
    </span>
  )
}
