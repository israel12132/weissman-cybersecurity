import { useRef } from 'react'
import { featuredRail } from '../content/resources'

export function FeaturedRail() {
  const scroller = useRef<HTMLUListElement>(null)

  function scroll(dir: number) {
    scroller.current?.scrollBy({ left: dir * 320, behavior: 'smooth' })
  }

  return (
    <section className="border-b border-[var(--line)] py-10" aria-labelledby="featured-heading">
      <div className="site-wrap">
        <div className="mb-4 flex items-end justify-between gap-4">
          <div>
            <p className="eyebrow">Featured</p>
            <h2 id="featured-heading" className="mt-1 text-xl text-ink">
              From the platform
            </h2>
          </div>
          <div className="flex gap-2">
            <button type="button" className="min-h-11 min-w-11 rounded-[12px] border border-[var(--line)]" onClick={() => scroll(-1)} aria-label="Previous featured">
              ←
            </button>
            <button type="button" className="min-h-11 min-w-11 rounded-[12px] border border-[var(--line)]" onClick={() => scroll(1)} aria-label="Next featured">
              →
            </button>
          </div>
        </div>
        <ul
          ref={scroller}
          className="flex snap-x snap-mandatory gap-4 overflow-x-auto pb-2 [-ms-overflow-style:none] [scrollbar-width:none] [&::-webkit-scrollbar]:hidden"
        >
          {featuredRail.map((item) => (
            <li key={item.id} className="w-[min(20rem,80vw)] shrink-0 snap-start">
              <a className="surface block h-full p-5 transition duration-base hover:-translate-y-0.5 hover:border-accent/40" href={item.href}>
                <p className="text-[0.7rem] uppercase tracking-[0.14em] text-dim">{item.type}</p>
                <h3 className="mt-2 text-lg text-ink">{item.title}</h3>
                <p className="mt-2 text-sm text-muted">{item.summary}</p>
              </a>
            </li>
          ))}
        </ul>
      </div>
    </section>
  )
}
