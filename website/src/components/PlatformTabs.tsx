import { useState } from 'react'
import { platformTabs, type Product } from '../content/products'
import { ButtonLink } from './Button'
import { ProductVisual } from './ProductVisual'

const accentVar: Record<Product['accent'], string> = {
  accent: 'var(--accent)',
  risk: 'var(--risk)',
  ops: 'var(--ops)',
}

export function PlatformTabs() {
  const [id, setId] = useState(platformTabs[0].id)
  const active = platformTabs.find((p) => p.id === id) ?? platformTabs[0]
  const color = accentVar[active.accent]

  return (
    <div>
      <div role="tablist" aria-label="Platform areas" className="-mx-2 flex gap-2 overflow-x-auto px-2 pb-4">
        {platformTabs.map((p) => (
          <button
            key={p.id}
            type="button"
            role="tab"
            aria-selected={p.id === id}
            id={`tab-${p.id}`}
            aria-controls={`panel-${p.id}`}
            className={`min-h-11 shrink-0 rounded-[12px] px-4 text-sm ${p.id === id ? 'bg-elevated text-ink' : 'text-muted hover:text-ink'}`}
            onClick={() => setId(p.id)}
          >
            {p.eyebrow}
          </button>
        ))}
      </div>
      <div
        role="tabpanel"
        id={`panel-${active.id}`}
        aria-labelledby={`tab-${active.id}`}
        className="grid gap-8 lg:grid-cols-12"
        style={{ ['--tab-accent' as string]: color }}
      >
        <div className="lg:col-span-6">
          <p className="text-sm font-semibold" style={{ color }}>
            {active.eyebrow}
          </p>
          <h3 className="mt-2 display text-3xl text-ink">{active.title}</h3>
          <p className="mt-4 text-muted">{active.summary}</p>
          <ul className="mt-6 space-y-2 text-sm text-muted">
            {active.capabilities.slice(0, 4).map((c) => (
              <li key={c} className="flex gap-2">
                <span aria-hidden style={{ color }}>
                  ▸
                </span>
                {c}
              </li>
            ))}
          </ul>
          <div className="mt-8">
            <ButtonLink href={active.href}>{active.ctaLabel}</ButtonLink>
          </div>
        </div>
        <div className="lg:col-span-6">
          <ProductVisual accent={color} />
        </div>
      </div>
    </div>
  )
}
