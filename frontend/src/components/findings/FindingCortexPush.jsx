import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Loader2, Radio } from 'lucide-react'
import { apiFetch } from '../../utils/apiFetch'
import Button from '../ui/Button'
import { findingVerifyId, liveVerdictFromFinding } from './FindingLiveVerify'

export function canPushFindingToCortex(finding) {
  const verdict = String(liveVerdictFromFinding(finding) || '').toUpperCase()
  if (verdict === 'NOISE' || verdict === 'FALSE_POSITIVE') return false
  const status = String(finding?.status || finding?.raw?.status || '').toUpperCase()
  if (['FALSE_POSITIVE', 'REJECTED', 'SUPPRESSED', 'NOISE'].includes(status)) return false
  if (verdict === 'CONFIRMED' || verdict === 'LIKELY_VALID') return true
  const raw = finding?.raw && typeof finding.raw === 'object' ? finding.raw : finding || {}
  const keys = ['proof', 'poc', 'poc_exploit', 'oast', 'oast_callback', 'http_status', 'evidence', 'http_evidence']
  const isProof = (v) => {
    if (v === true) return true
    if (typeof v === 'number') return v !== 0
    if (typeof v === 'string') {
      const t = v.trim()
      return Boolean(t) && !t.includes('[SEALED') && t !== '••••••••'
    }
    if (v && typeof v === 'object' && Object.keys(v).length) return true
    return false
  }
  const scan = (obj) => Boolean(obj && typeof obj === 'object' && keys.some((k) => isProof(obj[k])))
  return scan(raw) || scan(raw.raw) || scan(raw.evidence)
}

export default function FindingCortexPush({ finding }) {
  const { t } = useTranslation()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)
  const rawId = useMemo(() => findingVerifyId(finding), [finding])
  const eligible = canPushFindingToCortex(finding)

  const run = async (e) => {
    e?.preventDefault?.()
    e?.stopPropagation?.()
    if (!rawId || loading || !eligible) return
    setLoading(true)
    setError('')
    setResult(null)
    try {
      const data = await apiFetch(`/api/findings/${encodeURIComponent(rawId)}/push-cortex`, {
        method: 'POST',
        body: { dry_run: false },
      })
      if (data?.ok === false) throw new Error(data.detail || t('findings.cortexPush.failed'))
      setResult(data)
    } catch (err) {
      setError(err.message || t('findings.cortexPush.failed'))
    } finally {
      setLoading(false)
    }
  }

  return (
    <span className="inline-flex flex-col items-start gap-1">
      <Button
        variant="unstyled"
        type="button"
        onClick={run}
        disabled={loading || !rawId || !eligible}
        data-testid="push-cortex"
        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-mono border border-orange-500/35 bg-orange-500/10 text-orange-100 hover:bg-orange-500/20 disabled:opacity-40"
        title={eligible ? t('findings.cortexPush.hint') : t('findings.cortexPush.need_proof')}
      >
        {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Radio className="w-3.5 h-3.5" />}
        {t('findings.cortexPush.button')}
      </Button>
      {error && (
        <span role="alert" className="text-[9px] font-mono text-rose-300/90 max-w-[18rem] leading-snug">
          {error}
        </span>
      )}
      {result?.ok && (
        <span className="text-[9px] font-mono text-orange-200/90 max-w-[18rem] leading-snug">
          {result.xdr_had_matching_alert === false
            ? t('findings.cortexPush.blind_spot')
            : result.xdr_had_matching_alert === true
              ? t('findings.cortexPush.xdr_already')
              : result.detail || t('findings.cortexPush.ok')}
        </span>
      )}
    </span>
  )
}
