import { Link, Navigate, useLocation, useNavigate } from 'react-router'
import { Trans, useTranslation } from 'react-i18next'
import { useAuth } from '../../context/AuthContext'
import Button from '../ui/Button'

export default function CeoProtectedRoute({ children }) {
  const { isAuthenticated, isLoading, isCeo, logout } = useAuth()
  const { t } = useTranslation()
  const location = useLocation()
  const navigate = useNavigate()

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#030712]">
        <div className="flex flex-col items-center gap-4">
          <div className="w-10 h-10 border-2 border-emerald-500/30 border-t-emerald-400 rounded-full animate-spin" />
          <span className="text-xs font-mono text-[var(--text-muted)] uppercase tracking-widest">
            {t('components.ceo.protectedRoute.verifying')}
          </span>
        </div>
      </div>
    )
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />
  }

  if (!isCeo) {
    return (
      <div
        role="alert"
        className="min-h-screen flex flex-col items-center justify-center bg-[var(--bg-0)] text-[var(--text-secondary)] px-6"
      >
        <h1 className="text-xl font-semibold text-red-400 mb-2">{t('auth.access_denied')}</h1>
        <p className="text-sm text-[var(--text-tertiary)] text-center max-w-md mb-6">
          <Trans
            i18nKey="components.ceo.protectedRoute.requiresRole"
            components={{
              1: <span className="text-[var(--text-secondary)]" />,
              2: <span className="text-[var(--text-secondary)]" />,
            }}
          />
        </p>
        <div className="flex flex-col sm:flex-row gap-4 items-center">
          <Button variant="unstyled"
            type="button"
            className="text-sm font-mono text-amber-200 border border-amber-500/40 rounded px-4 py-2 hover:bg-amber-950/40"
            onClick={async () => {
              await logout()
              navigate('/login', { replace: true, state: { from: location } })
            }}
          >
            {t('auth.sign_in_again')}
          </Button>
          <Link
            to="/operations"
            className="text-sm font-mono text-cyan-400 hover:text-cyan-300 underline underline-offset-4"
          >
            {t('auth.open_operator_cockpit')}
          </Link>
        </div>
      </div>
    )
  }

  return children
}
