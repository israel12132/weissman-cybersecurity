import { useMemo, useState } from 'react'
import { resources, resourceTypes, type ResourceType } from '../content/resources'

export function ResourceGrid() {
  const [type, setType] = useState<ResourceType | 'all'>('all')
  const rows = useMemo(() => resources.filter((r) => type === 'all' || r.type === type), [type])

  return (
    <div>
      <div role="group" aria-label="Filter resources" className="mb-8 flex flex-wrap gap-2">
        {resourceTypes.map((t) => (
          <button
            key={t.id}
            type="button"
            className={`min-h-11 rounded-[12px] px-4 text-sm ${type === t.id ? 'bg-accent text-[#041016]' : 'border border-[var(--line)] text-muted'}`}
            aria-pressed={type === t.id}
            onClick={() => setType(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>
      {rows.length === 0 ? (
        <p className="text-muted">No published items in this category yet.</p>
      ) : (
        <ul className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {rows.map((r) => (
            <li key={r.id}>
              <a className="surface block h-full p-5 transition duration-base hover:-translate-y-0.5 hover:border-accent/40" href={r.href}>
                <p className="text-[0.7rem] uppercase tracking-[0.14em] text-dim">{r.type}</p>
                <h3 className="mt-2 text-lg text-ink">{r.title}</h3>
                <p className="mt-2 text-sm text-muted">{r.summary}</p>
                {r.date && <p className="mt-3 font-mono text-xs text-dim">{r.date}</p>}
              </a>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
