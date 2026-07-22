import { forwardRef } from 'react'
import { cn } from '../../lib/cn'

const STATUS = {
  covered: { dot: 'bg-status-active', label: 'Covered' },
  partial: { dot: 'bg-severity-medium', label: 'Partial' },
  gap: { dot: 'bg-severity-critical', label: 'Gap' },
  na: { dot: 'bg-border-strong', label: 'N/A' },
}

const STATUS_ORDER = ['covered', 'partial', 'gap', 'na']

/**
 * ComplianceMatrix — a control × framework coverage grid (ISO / SOC 2 / NIST /
 * CIS …). Each cell shows a status dot with an accessible label; cells are
 * clickable to drill into the mapping.
 *
 * @param {Array<{id:string,label:React.ReactNode}>} frameworks — matrix columns
 * @param {Array<{id?:string,label:React.ReactNode,status:Record<string,'covered'|'partial'|'gap'|'na'>}>} controls — rows
 * @param {(control:object,frameworkId:string,status:string)=>void} [onCellClick]
 * @param {string} [title='Compliance coverage']
 */
const ComplianceMatrix = forwardRef(function ComplianceMatrix(
  { frameworks = [], controls = [], onCellClick, title = 'Compliance coverage', className, ...props },
  ref,
) {
  const interactive = typeof onCellClick === 'function'

  return (
    <div ref={ref} className={cn('flex flex-col gap-3', className)} {...props}>
      <div className="overflow-x-auto custom-scroll rounded-xl border border-border-default">
        <table className="w-full border-collapse text-sm">
          <caption className="sr-only">{title}</caption>
          <thead>
            <tr className="border-b border-border-subtle">
              <th className="px-3 py-2 text-start text-[10px] font-medium uppercase tracking-widest text-text-muted">
                Control
              </th>
              {frameworks.map((fw) => (
                <th
                  key={fw.id}
                  scope="col"
                  className="px-3 py-2 text-center text-[10px] font-medium uppercase tracking-widest text-text-muted whitespace-nowrap"
                >
                  {fw.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {controls.map((ctrl, i) => (
              <tr key={ctrl.id ?? i} className="border-b border-border-subtle last:border-0">
                <th scope="row" className="px-3 py-2 text-start text-xs font-normal text-text-secondary">
                  {ctrl.label}
                </th>
                {frameworks.map((fw) => {
                  const key = ctrl.status?.[fw.id] ?? 'na'
                  const meta = STATUS[key] ?? STATUS.na
                  const cellLabel = `${typeof ctrl.label === 'string' ? ctrl.label : 'Control'} · ${typeof fw.label === 'string' ? fw.label : fw.id}: ${meta.label}`
                  const dot = (
                    <span className={cn('inline-block size-2.5 rounded-full', meta.dot)} aria-hidden="true" />
                  )
                  return (
                    <td key={fw.id} className="px-3 py-2 text-center">
                      {interactive ? (
                        <button
                          type="button"
                          onClick={() => onCellClick(ctrl, fw.id, key)}
                          aria-label={cellLabel}
                          className="inline-flex items-center justify-center rounded p-1 focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)] hover:bg-bg-2"
                        >
                          {dot}
                        </button>
                      ) : (
                        <span aria-label={cellLabel} role="img">
                          {dot}
                        </span>
                      )}
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap items-center gap-3">
        {STATUS_ORDER.map((k) => (
          <span key={k} className="inline-flex items-center gap-1.5 text-[11px] text-text-tertiary">
            <span className={cn('size-2.5 rounded-full', STATUS[k].dot)} aria-hidden="true" />
            {STATUS[k].label}
          </span>
        ))}
      </div>
    </div>
  )
})

ComplianceMatrix.displayName = 'ComplianceMatrix'

export default ComplianceMatrix
export { ComplianceMatrix }
