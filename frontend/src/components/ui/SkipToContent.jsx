import React from 'react'
import { useTranslation } from 'react-i18next'

/**
 * Visually hidden until focused — WCAG 2.4.1 bypass block.
 * Targets #main-content, which each major layout must expose.
 */
export default function SkipToContent() {
  const { t } = useTranslation()
  return (
    <a
      href="#main-content"
      className="skip-to-content"
    >
      {t('a11y.skip_to_content')}
    </a>
  )
}
