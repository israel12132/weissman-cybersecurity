
import { Navigate, useLocation } from 'react-router'
import { useTranslation } from 'react-i18next'
import { useAuth } from '../../context/AuthContext'

export default function ProtectedRoute({ children }) {
  const { t } = useTranslation()
  const { isAuthenticated, isLoading } = useAuth()
  const location = useLocation()

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#050505]">
        <div className="flex flex-col items-center gap-4">
          <div className="w-8 h-8 border-2 border-[#22d3ee]/30 border-t-[#22d3ee] rounded-full animate-spin" />
          <span className="text-xs font-mono text-[#6b7280] uppercase tracking-widest">{t('components.cockpitWidgets.protectedRoute.verifying')}</span>
        </div>
      </div>
    )
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />
  }

  return children
}
