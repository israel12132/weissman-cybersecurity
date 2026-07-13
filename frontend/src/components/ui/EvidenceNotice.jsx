
/**
 * Standard cyan banner citing live API data sources — no simulated telemetry.
 */
export default function EvidenceNotice({ children, className = '' }) {
  if (!children) return null
  return (
    <div
      className={`rounded-xl border border-cyan-500/20 bg-cyan-500/5 px-4 py-3 text-[11px] font-mono text-cyan-200/80 leading-relaxed ${className}`}
      role="note"
    >
      {children}
    </div>
  )
}
