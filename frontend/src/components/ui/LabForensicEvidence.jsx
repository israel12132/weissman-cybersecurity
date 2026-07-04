/**
 * Forensic evidence banner for standalone lab / war-room panels.
 * Resolves copy from routeEvidence or an explicit i18n key.
 */
import { useLocation } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import EvidenceNotice from './EvidenceNotice'
import { resolveRouteEvidence } from '../../lib/routeEvidence'

export default function LabForensicEvidence({ i18nKey, className = 'mb-4' }) {
  const { t } = useTranslation()
  const { pathname } = useLocation()
  const text = i18nKey ? t(i18nKey) : resolveRouteEvidence(pathname, t)
  if (!text || (i18nKey && text === i18nKey)) return null
  return <EvidenceNotice className={className}>{text}</EvidenceNotice>
}
