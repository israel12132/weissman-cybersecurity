import { useRef, type MouseEvent } from 'react'
import { metrics } from '../content/metrics'
import { useI18n } from '../i18n'
import { ButtonLink } from './Button'
import { ProductVisual } from './ProductVisual'

const HERO_METRICS = ['productionEngines', 'liveProbes', 'mitreTechniques', 'commandCenterRoutes'] as const

export function Hero() {
  const { t, n } = useI18n()
  const stage = useRef<HTMLDivElement>(null)

  function onMove(e: MouseEvent<HTMLDivElement>) {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return
    const el = stage.current
    if (!el) return
    const r = el.getBoundingClientRect()
    const x = (e.clientX - r.left) / r.width - 0.5
    const y = (e.clientY - r.top) / r.height - 0.5
    el.style.setProperty('--px', x.toFixed(3))
    el.style.setProperty('--py', y.toFixed(3))
  }

  return (
    <header className="relative overflow-hidden border-b border-[var(--line)]">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_80%_60%_at_70%_0%,rgba(34,211,238,0.14),transparent_55%),linear-gradient(180deg,#0b1016_0%,#07090c_70%)]" />
      <div className="pointer-events-none absolute inset-0 opacity-40 [background-image:linear-gradient(rgba(244,239,230,0.04)_1px,transparent_1px),linear-gradient(90deg,rgba(244,239,230,0.04)_1px,transparent_1px)] [background-size:48px_48px]" />
      <div className="site-wrap relative grid items-center gap-12 py-16 md:py-24 lg:grid-cols-12">
        <div className="lg:col-span-6">
          <p className="eyebrow mb-5">{t('hero.kicker')}</p>
          <h1 className="display text-4xl text-ink md:text-6xl">{t('hero.h1')}</h1>
          <p className="mt-6 max-w-xl text-lg leading-relaxed text-muted">
            {t('hero.lead', { engines: n(metrics.productionEngines.value) })}
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <ButtonLink href="/contact/">{t('cta.bookDemo')}</ButtonLink>
            <ButtonLink variant="ghost" href="/platform/">
              {t('cta.explorePlatform')}
            </ButtonLink>
          </div>
          <dl className="mt-10 grid grid-cols-2 gap-4 sm:grid-cols-4">
            {HERO_METRICS.map((key) => {
              const value = metrics[key].value
              return (
              <div key={key}>
                <dt className="text-[0.68rem] uppercase tracking-[0.14em] text-dim">{t(`metrics.${key}`)}</dt>
                <dd className="mt-1 font-mono text-2xl text-accent" dir="ltr">
                  {n(value)}
                </dd>
              </div>
              )
            })}
          </dl>
        </div>
        <div
          ref={stage}
          onMouseMove={onMove}
          className="lg:col-span-6"
          style={{ transform: 'translate3d(calc(var(--px,0)*10px), calc(var(--py,0)*8px), 0)' }}
        >
          <ProductVisual />
        </div>
      </div>
    </header>
  )
}
