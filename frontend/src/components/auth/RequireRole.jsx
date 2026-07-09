import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useAuth } from '../../context/AuthContext'

/**
 * Route/section guard enforcing a minimum RBAC role.
 *
 * Defense-in-depth only — the backend independently 403s privileged calls.
 * This prevents an authenticated lower-privilege user from URL-hopping into a
 * privileged page shell (e.g. /admin, /system-config, /ceo-vault) and having
 * it render before the data calls fail.
 *
 * @param {{ min: string, children: React.ReactNode }} props `min` is a role
 *   from the ladder (viewer→analyst→operator→admin→ceo→superadmin).
 */
export default function RequireRole({ min = 'admin', children }) {
  const { isAuthenticated, isLoading, hasRole, role, logout } = useAuth()
  const { t } = useTranslation()
  const location = useLocation()
  const navigate = useNavigate()

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#030712]">
        <div className="flex flex-col items-center gap-4">
          <div className="w-10 h-10 border-2 border-cyan-500/30 border-t-cyan-400 rounded-full animate-spin" />
          <span className="text-xs font-mono text-slate-500 uppercase tracking-widest">
            {t('auth.verifying_access')}
          </span>
        </div>
      </div>
    )
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />
  }

  if (!hasRole(min)) {
    return (
      <div
        role="alert"
        className="min-h-screen flex flex-col items-center justify-center bg-[var(--bg-0)] text-[var(--text-secondary)] px-6"
      >
        <h1 className="text-xl font-semibold text-red-400 mb-2">
          {t('auth.access_denied')}
        </h1>
        <p className="text-sm text-[var(--text-muted)] text-center max-w-md mb-6">
          {t('auth.requires_role', { min, role })}
        </p>
        <div className="flex flex-col sm:flex-row gap-4 items-center">
          <button
            type="button"
            className="text-sm font-mono text-amber-200 border border-amber-500/40 rounded px-4 py-2 hover:bg-amber-950/40"
            onClick={async () => {
              await logout()
              navigate('/login', { replace: true, state: { from: location } })
            }}
          >
            {t('auth.sign_in_again')}
          </button>
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
