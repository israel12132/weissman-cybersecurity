import { useState } from 'react'
import { platformTabs, type Product } from '../content/products'
import { useI18n } from '../i18n'
import { ButtonLink } from './Button'
import { ProductVisual } from './ProductVisual'

const accentVar: Record<Product['accent'], string> = {
  accent: 'var(--accent)',
  risk: 'var(--risk)',
  ops: 'var(--ops)',
}

export function PlatformTabs() {
  const { t } = useI18n()
  const [id, setId] = useState(platformTabs[0].id)
  const active = platformTabs.find((p) => p.id === id) ?? platformTabs[0]
  const color = accentVar[active.accent]

  return (
    <div>
      <div role="tablist" aria-label={t('a11y.platformAreas')} className="-mx-2 flex gap-2 overflow-x-auto px-2 pb-4">
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
            {t(`products.${p.id}.eyebrow`)}
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
            {t(`products.${active.id}.eyebrow`)}
          </p>
          <h3 className="mt-2 display text-3xl text-ink">{t(`products.${active.id}.title`)}</h3>
          <p className="mt-4 text-muted">{t(`products.${active.id}.summary`)}</p>
          <ul className="mt-6 space-y-2 text-sm text-muted">
            {[0, 1, 2, 3].map((i) => (
              <li key={i} className="flex gap-2">
                <span aria-hidden style={{ color }}>
                  ▸
                </span>
                {t(`products.${active.id}.capabilities.${i}`)}
              </li>
            ))}
          </ul>
          <div className="mt-8">
            <ButtonLink href={active.href}>{t(`products.${active.id}.ctaLabel`)}</ButtonLink>
          </div>
        </div>
        <div className="lg:col-span-6">
          <ProductVisual accent={color} />
        </div>
      </div>
    </div>
  )
}
