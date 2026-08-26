import { useMemo, useState } from 'react'
import { resources, resourceTypeIds, type ResourceType } from '../content/resources'
import { useI18n } from '../i18n'
import { A } from './A'

export function ResourceGrid() {
  const { t, date } = useI18n()
  const [type, setType] = useState<ResourceType | 'all'>('all')
  const rows = useMemo(() => resources.filter((r) => type === 'all' || r.type === type), [type])

  return (
    <div>
      <div role="group" aria-label={t('a11y.resourceFilter')} className="mb-8 flex flex-wrap gap-2">
        {resourceTypeIds.map((id) => (
          <button
            key={id}
            type="button"
            className={`min-h-11 rounded-[12px] px-4 text-sm ${type === id ? 'bg-accent text-[#041016]' : 'border border-[var(--line)] text-muted'}`}
            aria-pressed={type === id}
            onClick={() => setType(id)}
          >
            {t(`resourcesPage.types.${id}`)}
          </button>
        ))}
      </div>
      {rows.length === 0 ? (
        <p className="text-muted">{t('resourcesPage.empty')}</p>
      ) : (
        <ul className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {rows.map((r) => (
            <li key={r.id}>
              <A className="surface block h-full p-5 transition duration-base hover:-translate-y-0.5 hover:border-accent/40" href={r.href}>
                <p className="text-[0.7rem] uppercase tracking-[0.14em] text-dim">{t(`resourcesPage.types.${r.type}`)}</p>
                <h3 className="mt-2 text-lg text-ink">{t(`resourcesPage.items.${r.id}.title`)}</h3>
                <p className="mt-2 text-sm text-muted">{t(`resourcesPage.items.${r.id}.summary`)}</p>
                {r.date && (
                  <p className="mt-3 font-mono text-xs text-dim">
                    {date(r.date)}
                  </p>
                )}
              </A>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
