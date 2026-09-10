import { howItWorksIds } from '../content/site'
import { useI18n } from '../i18n'
import { Reveal } from './Reveal'

export function ProcessTimeline() {
  const { t } = useI18n()
  return (
    <ol className="relative grid gap-4 md:grid-cols-4 md:gap-0">
      {howItWorksIds.map((id, i) => (
        <li key={id} className="relative">
          {i < howItWorksIds.length - 1 && (
            <span
              aria-hidden
              className="pointer-events-none absolute start-[2.25rem] top-7 hidden h-px bg-gradient-to-r from-accent/70 to-transparent md:block md:end-0 rtl:bg-gradient-to-l"
            />
          )}
          <Reveal>
            <article className="relative pe-4 md:pe-8">
              <p className="font-mono text-xs text-ops">0{i + 1}</p>
              <h3 className="mt-3 text-xl text-ink">{t(`howItWorks.${id}.title`)}</h3>
              <p className="mt-3 text-sm leading-relaxed text-muted">{t(`howItWorks.${id}.body`)}</p>
            </article>
          </Reveal>
        </li>
      ))}
    </ol>
  )
}
