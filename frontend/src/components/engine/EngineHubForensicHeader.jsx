/**
 * Forensic evidence + WASM-verified reality badge for standalone engine hub pages.
 */
import EvidenceNotice from '../ui/EvidenceNotice'
import ForensicEngineRealityBadge from '../../forensic/ForensicEngineRealityBadge'

export default function EngineHubForensicHeader({ evidence, engineId, className = 'mb-6' }) {
  return (
    <div className={className}>
      {evidence ? <EvidenceNotice className="mb-4">{evidence}</EvidenceNotice> : null}
      {engineId ? (
        <div className="flex flex-wrap items-center gap-2">
          <ForensicEngineRealityBadge engineId={engineId} size="sm" showRemote showCanonical />
        </div>
      ) : null}
    </div>
  )
}
