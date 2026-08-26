import { useI18n } from '../i18n'

const KEYS = ['after', 'during', 'who', 'value'] as const

export function DemoJourney() {
  const { t } = useI18n()
  return (
    <ul className="space-y-5">
      {KEYS.map((k) => (
        <li key={k}>
          <p className="font-mono text-[11px] tracking-[0.12em] text-accent">{t(`demoJourney.${k}.title`)}</p>
          <p className="mt-1 text-sm leading-relaxed text-muted">{t(`demoJourney.${k}.body`)}</p>
        </li>
      ))}
    </ul>
  )
}
