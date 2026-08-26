import { metrics } from '../content/metrics'
import { useI18n } from '../i18n'
import { AttackTheater } from './AttackTheater'
import { ButtonLink } from './Button'
import { MetricCounter } from './MetricCounter'

const HERO_METRICS = ['productionEngines', 'liveProbes', 'mitreTechniques', 'commandCenterRoutes'] as const

export function Hero() {
  const { t, n } = useI18n()

  return (
    <header className="relative overflow-hidden border-b border-[var(--line)]">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_80%_60%_at_78%_-10%,rgba(34,211,238,0.16),transparent_50%),radial-gradient(ellipse_50%_40%_at_10%_80%,rgba(62,224,178,0.07),transparent_50%),linear-gradient(180deg,#0b1016_0%,#07090c_78%)]" />
      <div className="pointer-events-none absolute inset-0 opacity-35 [background-image:linear-gradient(rgba(244,239,230,0.045)_1px,transparent_1px),linear-gradient(90deg,rgba(244,239,230,0.045)_1px,transparent_1px)] [background-size:56px_56px]" />
      <div className="site-wrap relative grid items-center gap-12 py-16 md:py-20 lg:grid-cols-12 lg:py-24">
        <div className="lg:col-span-5">
          <p className="eyebrow mb-5">{t('hero.kicker')}</p>
          <h1 className="display text-4xl text-ink md:text-6xl">{t('hero.h1')}</h1>
          <p className="mt-6 max-w-xl text-lg leading-relaxed text-muted">
            {t('hero.lead', { engines: n(metrics.productionEngines.value) })}
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <ButtonLink href="/contact/" analyticsEvent="demo_cta_click" analyticsPayload={{ placement: 'hero' }}>
              {t('cta.bookDemo')}
            </ButtonLink>
            <ButtonLink
              variant="ghost"
              href="/platform/"
              analyticsEvent="platform_cta_click"
              analyticsPayload={{ placement: 'hero' }}
            >
              {t('cta.explorePlatform')}
            </ButtonLink>
          </div>
          <dl className="mt-10 grid grid-cols-2 gap-4 sm:grid-cols-4">
            {HERO_METRICS.map((key) => (
              <div key={key}>
                <dt className="text-[0.68rem] tracking-[0.14em] text-dim">{t(`metrics.${key}`)}</dt>
                <dd className="mt-1 font-mono text-2xl text-accent">
                  <MetricCounter value={metrics[key].value} />
                </dd>
              </div>
            ))}
          </dl>
          <a
            href="#why-us"
            className="mt-10 inline-flex min-h-11 items-center gap-2 text-sm text-dim transition duration-swift hover:text-ink"
          >
            <span aria-hidden className="hero-scroll-cue inline-block h-8 w-px bg-accent/70" />
            {t('hero.scrollCue')}
          </a>
        </div>
        <div className="lg:col-span-7">
          <AttackTheater />
        </div>
      </div>
    </header>
  )
}
