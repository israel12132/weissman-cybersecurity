import { CUSTOMER_LOGIN_HREF } from '../content/site'
import { useI18n } from '../i18n'
import { ButtonLink } from './Button'

export function CustomerLoginLink({
  variant = 'ghost',
  className = '',
}: {
  variant?: 'primary' | 'ghost' | 'text'
  className?: string
}) {
  const { t } = useI18n()
  return (
    <ButtonLink
      variant={variant}
      href={CUSTOMER_LOGIN_HREF}
      className={className}
      analyticsEvent="nav_interact"
      analyticsPayload={{ item: 'customer_login' }}
    >
      {t('cta.customerLogin')}
    </ButtonLink>
  )
}
