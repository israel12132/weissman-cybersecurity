import { useRef } from 'react'
import { featuredRail } from '../content/resources'
import { useI18n } from '../i18n'
import { A } from './A'

export function FeaturedRail() {
  const { t, dir } = useI18n()
  const scroller = useRef<HTMLUListElement>(null)

  function scroll(dirN: number) {
    const sign = dir === 'rtl' ? -1 : 1
    scroller.current?.scrollBy({ left: dirN * sign * 320, behavior: 'smooth' })
  }

  return (
    <section className="border-b border-[var(--line)] py-10" aria-labelledby="featured-heading">
      <div className="site-wrap">
        <div className="mb-4 flex items-end justify-between gap-4">
          <div>
            <p className="eyebrow">{t('featured.eyebrow')}</p>
            <h2 id="featured-heading" className="mt-1 text-xl text-ink">
              {t('featured.title')}
            </h2>
          </div>
          <div className="flex gap-2">
            <button type="button" className="min-h-11 min-w-11 rounded-[12px] border border-[var(--line)]" onClick={() => scroll(-1)} aria-label={t('a11y.featuredPrev')}>
              <span aria-hidden className="rtl:inline-block rtl:rotate-180">
                ←
              </span>
            </button>
            <button type="button" className="min-h-11 min-w-11 rounded-[12px] border border-[var(--line)]" onClick={() => scroll(1)} aria-label={t('a11y.featuredNext')}>
              <span aria-hidden className="rtl:inline-block rtl:rotate-180">
                →
              </span>
            </button>
          </div>
        </div>
        <ul
          ref={scroller}
          className="flex snap-x snap-mandatory gap-4 overflow-x-auto pb-2 [-ms-overflow-style:none] [scrollbar-width:none] [&::-webkit-scrollbar]:hidden"
        >
          {featuredRail.map((item) => (
            <li key={item.id} className="w-[min(20rem,80vw)] shrink-0 snap-start">
              <A className="surface block h-full p-5 transition duration-base hover:-translate-y-0.5 hover:border-accent/40" href={item.href}>
                <p className="text-[0.7rem] uppercase tracking-[0.14em] text-dim">{t(`resourcesPage.types.${item.type}`)}</p>
                <h3 className="mt-2 text-lg text-ink">{t(`resourcesPage.items.${item.id}.title`)}</h3>
                <p className="mt-2 text-sm text-muted">{t(`resourcesPage.items.${item.id}.summary`)}</p>
              </A>
            </li>
          ))}
        </ul>
      </div>
    </section>
  )
}
