import { useI18n } from '../i18n'

export function SkipLink() {
  const { t } = useI18n()
  return (
    <a
      href="#main"
      className="sr-only focus:not-sr-only focus:absolute focus:inset-inline-start-4 focus:top-4 focus:z-[80] focus:rounded-[10px] focus:bg-accent focus:px-4 focus:py-2 focus:text-sm focus:font-semibold focus:text-[#041016]"
    >
      {t('a11y.skip')}
    </a>
  )
}
