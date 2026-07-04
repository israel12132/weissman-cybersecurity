/**
 * AppShell wrapper for standalone lab / war-room panels (no engine C2 chrome).
 */
import AppShell from '../layout/AppShell'
import LabForensicEvidence from './LabForensicEvidence'

export default function StandaloneLabShell({
  title,
  subtitle,
  children,
  actions,
  contentClassName,
  maxWidth,
}) {
  return (
    <AppShell
      title={title}
      subtitle={subtitle}
      actions={actions}
      contentClassName={contentClassName}
      maxWidth={maxWidth}
    >
      <LabForensicEvidence />
      {children}
    </AppShell>
  )
}
