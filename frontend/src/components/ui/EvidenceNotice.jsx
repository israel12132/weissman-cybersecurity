
/**
 * Standard cyan banner citing live API data sources — no simulated telemetry.
 */
export default function EvidenceNotice({ children, className = '' }) {
  if (!children) return null
  return (
    <div
      className={`rounded-xl border border-[var(--border-accent)] bg-[var(--accent-cyan-muted)] px-4 py-3 text-[11px] font-mono text-[var(--text-accent)] leading-relaxed ${className}`}
      role="note"
    >
      {children}
    </div>
  )
}
