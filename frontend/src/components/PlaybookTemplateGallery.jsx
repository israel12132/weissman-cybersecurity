import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Plus,
  Search,
  ShieldAlert,
  Fingerprint,
  Globe,
  KeyRound,
  Cloud,
  GitBranch,
  Crosshair,
  Sparkles,
  Trash2,
  Zap,
} from 'lucide-react'
import Button from './ui/Button'
import {
  PLAYBOOK_CATEGORIES,
  actionKindLabel,
  filterCatalog,
} from '../lib/playbookCatalog'

const CATEGORY_ICON = {
  containment: ShieldAlert,
  identity: Fingerprint,
  exposure: Globe,
  secrets: KeyRound,
  cloud: Cloud,
  supply_chain: GitBranch,
  threat: Crosshair,
  custom: Sparkles,
}

const INTENSITY_CLS = {
  critical: 'bg-rose-500/15 text-rose-200 ring-rose-500/35',
  high: 'bg-orange-500/15 text-orange-200 ring-orange-500/35',
  medium: 'bg-amber-500/15 text-amber-200 ring-amber-500/35',
}

function templateTitle(template, t) {
  if (template.nameKey) return t(template.nameKey, template.fallbackName)
  return template.name || t('playbooks.catalog.untitled')
}

function templateBody(template, t) {
  if (template.descriptionKey) return t(template.descriptionKey, template.fallbackDescription)
  return template.description || ''
}

/**
 * Selectable catalog of built-in SOAR playbooks plus custom templates and a
 * blank-canvas card. Used as the builder empty state and inside the catalog modal.
 */
export default function PlaybookTemplateGallery({
  templates,
  onSelect,
  onCreateBlank,
  onDeleteCustom,
  compact = false,
}) {
  const { t } = useTranslation()
  const [query, setQuery] = useState('')
  const [category, setCategory] = useState('')

  const visible = useMemo(
    () => filterCatalog(templates, query, category, t),
    [templates, query, category, t],
  )

  const categories = useMemo(() => {
    const present = new Set((templates || []).map((p) => p.category).filter(Boolean))
    return PLAYBOOK_CATEGORIES.filter((c) => present.has(c))
  }, [templates])

  return (
    <div data-testid="playbook-catalog" className={compact ? '' : 'space-y-5'}>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h2 className="text-[15px] font-semibold tracking-tight text-[var(--text-primary)]">
            {t('playbooks.catalog.title')}
          </h2>
          <p className="mt-1 max-w-2xl text-[12px] leading-relaxed text-[var(--text-muted)]">
            {t('playbooks.catalog.subtitle')}
          </p>
        </div>
        <div className="relative min-w-[220px]">
          <Search className="pointer-events-none absolute start-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--text-disabled)]" />
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            aria-label={t('playbooks.catalog.search')}
            placeholder={t('playbooks.catalog.search')}
            className="w-full rounded-lg bg-[var(--bg-2)] py-2 ps-8 pe-3 text-[11px] text-[var(--text-secondary)] ring-1 ring-white/[0.08] placeholder:text-[var(--text-disabled)] focus:outline-none focus:ring-cyan-400/30"
          />
        </div>
      </div>

      <div className="flex flex-wrap gap-1.5" role="tablist" aria-label={t('playbooks.catalog.categories')}>
        <Button
          variant="unstyled"
          type="button"
          role="tab"
          aria-selected={category === ''}
          onClick={() => setCategory('')}
          className={`rounded-full px-3 py-1 text-[10px] font-semibold uppercase tracking-wider ring-1 transition-all ${
            category === ''
              ? 'bg-violet-500/20 text-violet-100 ring-violet-400/40'
              : 'bg-[var(--row-hover-bg)] text-[var(--text-muted)] ring-white/[0.08] hover:text-[var(--text-secondary)]'
          }`}
        >
          {t('playbooks.catalog.category_all')}
        </Button>
        {categories.map((c) => (
          <Button
            variant="unstyled"
            type="button"
            role="tab"
            key={c}
            aria-selected={category === c}
            onClick={() => setCategory(c)}
            className={`rounded-full px-3 py-1 text-[10px] font-semibold uppercase tracking-wider ring-1 transition-all ${
              category === c
                ? 'bg-cyan-500/15 text-cyan-100 ring-cyan-400/35'
                : 'bg-[var(--row-hover-bg)] text-[var(--text-muted)] ring-white/[0.08] hover:text-[var(--text-secondary)]'
            }`}
          >
            {t(`playbooks.catalog.category_${c}`)}
          </Button>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        {onCreateBlank && (
          <Button
            variant="unstyled"
            type="button"
            data-testid="playbook-blank"
            data-testid="playbook-blank"
            onClick={onCreateBlank}
            className="group flex min-h-[168px] flex-col items-start justify-between rounded-2xl border border-dashed border-violet-400/30 bg-gradient-to-br from-violet-500/[0.08] to-cyan-500/[0.04] p-4 text-start transition-all hover:border-violet-400/50 hover:from-violet-500/[0.14] hover:shadow-lg hover:shadow-violet-500/10"
          >
            <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-violet-500/20 text-violet-200 ring-1 ring-violet-400/30">
              <Plus className="h-5 w-5" />
            </span>
            <span>
              <span className="block text-[14px] font-semibold text-[var(--text-primary)]">
                {t('playbooks.catalog.blank_title')}
              </span>
              <span className="mt-1 block text-[12px] leading-relaxed text-[var(--text-muted)]">
                {t('playbooks.catalog.blank_desc')}
              </span>
            </span>
          </Button>
        )}

        {visible.map((template) => {
          const Icon = CATEGORY_ICON[template.category] || Zap
          const intensityCls = INTENSITY_CLS[template.intensity] || INTENSITY_CLS.medium
          const title = templateTitle(template, t)
          const body = templateBody(template, t)
          const kinds = (template.actions || []).map((a) => a.kind)
          return (
            <div
              key={template.id}
              data-testid={`playbook-template-${template.id}`}
              className="group relative flex min-h-[168px] flex-col rounded-2xl bg-[var(--bg-1)]/70 p-4 ring-1 ring-white/[0.08] transition-all hover:ring-violet-400/30 hover:shadow-lg hover:shadow-black/20"
            >
              <div className="mb-3 flex items-start justify-between gap-2">
                <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-[var(--row-hover-bg)] text-cyan-200 ring-1 ring-white/[0.08]">
                  <Icon className="h-4 w-4" aria-hidden="true" />
                </span>
                <span className="flex flex-wrap items-center justify-end gap-1">
                  <span className={`rounded-full px-2 py-0.5 text-[9px] font-semibold uppercase tracking-wider ring-1 ${intensityCls}`}>
                    {t(`playbooks.severity.${template.intensity || 'medium'}`, template.intensity || 'medium')}
                  </span>
                  <span className="rounded-full bg-[var(--row-hover-bg)] px-2 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-[var(--text-muted)] ring-1 ring-white/[0.08]">
                    {t(`playbooks.catalog.category_${template.category}`, template.category)}
                  </span>
                </span>
              </div>
              <h3 className="text-[13px] font-semibold leading-snug text-[var(--text-primary)]">{title}</h3>
              <p className="mt-1.5 line-clamp-3 flex-1 text-[11px] leading-relaxed text-[var(--text-muted)]">{body}</p>
              <div className="mt-3 flex flex-wrap gap-1">
                {kinds.slice(0, 4).map((kind) => (
                  <span key={kind} className="rounded bg-[var(--bg-2)] px-1.5 py-0.5 font-mono text-[9px] text-emerald-300/80">
                    {actionKindLabel(kind, t)}
                  </span>
                ))}
                {(template.trigger?.engines || []).slice(0, 2).map((eng) => (
                  <span key={eng} className="rounded bg-[var(--bg-2)] px-1.5 py-0.5 font-mono text-[9px] text-cyan-300/80">
                    {eng}
                  </span>
                ))}
              </div>
              <div className="mt-3 flex items-center gap-2">
                <Button
                  variant="unstyled"
                  type="button"
                  onClick={() => onSelect?.(template)}
                  className="inline-flex flex-1 items-center justify-center gap-1.5 rounded-lg bg-gradient-to-r from-violet-600/80 to-cyan-600/70 px-3 py-2 text-[11px] font-medium text-white transition-all hover:from-violet-500/90 hover:to-cyan-500/80"
                >
                  {t('playbooks.catalog.use')}
                </Button>
                {template.category === 'custom' && onDeleteCustom && (
                  <Button
                    variant="unstyled"
                    type="button"
                    aria-label={t('playbooks.catalog.delete_custom')}
                    onClick={() => onDeleteCustom(template.id)}
                    className="rounded-lg p-2 text-rose-300 ring-1 ring-rose-500/25 hover:bg-rose-500/10"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                )}
              </div>
            </div>
          )
        })}
      </div>

      {visible.length === 0 && (
        <p className="py-8 text-center text-[12px] text-[var(--text-muted)]">
          {t('playbooks.catalog.no_match')}
        </p>
      )}
    </div>
  )
}

export { templateTitle, templateBody }
