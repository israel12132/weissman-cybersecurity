import { useState, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import PageShell from '../../pages/PageShell'
import EvidenceNotice from '../ui/EvidenceNotice'
import ShellScanActions from '../engine/ShellScanActions'

/**
 * Standard shell for a cockpit widget promoted to its own menu route: the
 * forensic PageShell chrome, a live-evidence notice, and a Refresh action that
 * remounts the widget so it re-pulls from its production engine. The widget
 * itself is passed as children.
 */
export default function WidgetShell({ titleKey, badge, badgeColor, children }) {
  const { t } = useTranslation()
  const [nonce, setNonce] = useState(0)
  const reload = useCallback(() => setNonce((n) => n + 1), [])
  return (
    <PageShell
      title={t(titleKey)}
      subtitle={t('nav.widget_subtitle')}
      badge={badge}
      badgeColor={badgeColor}
      actions={<ShellScanActions onRefresh={() => reload()} />}
    >
      <EvidenceNotice>{t('nav.widget_evidence')}</EvidenceNotice>
      <div key={nonce} className="mt-3">
        {children}
      </div>
    </PageShell>
  )
}
