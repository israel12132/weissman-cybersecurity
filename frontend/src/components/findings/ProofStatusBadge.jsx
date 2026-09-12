import { ShieldCheck, ShieldAlert, Eye, Ban, FlaskConical } from 'lucide-react'
import { useTranslation } from 'react-i18next'

const META = {
  proven: { color: '#22c55e', icon: ShieldCheck },
  validated_safe_proof: { color: '#38bdf8', icon: FlaskConical },
  failed_proof: { color: '#f87171', icon: ShieldAlert },
  not_applicable: { color: '#94a3b8', icon: Ban },
  observed: { color: '#fbbf24', icon: Eye },
}

export function proofStatusOf(entity) {
  const raw = entity?.proof_status || entity?.proofStatus || ''
  const s = String(raw).trim().toLowerCase()
  return META[s] ? s : 'observed'
}

export default function ProofStatusBadge({ status, compact = false, className = '' }) {
  const { t } = useTranslation()
  const key = META[status] ? status : proofStatusOf({ proof_status: status })
  const meta = META[key] || META.observed
  const Icon = meta.icon
  return (
    <span
      className={`inline-flex items-center gap-1 rounded border font-mono uppercase tracking-wide ${
        compact ? 'text-[9px] px-1.5 py-0.5' : 'text-[10px] px-2 py-0.5'
      } ${className}`}
      style={{ color: meta.color, borderColor: `${meta.color}55`, background: `${meta.color}12` }}
      data-testid="proof-status-badge"
      data-proof-status={key}
    >
      <Icon className={compact ? 'w-3 h-3' : 'w-3.5 h-3.5'} />
      {t(`findings.proof.${key}`)}
    </span>
  )
}
