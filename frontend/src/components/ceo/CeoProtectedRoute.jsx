import React from 'react'
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '../../context/AuthContext'

export default function CeoProtectedRoute({ children }) {
  const { isAuthenticated, isLoading, isCeo, logout } = useAuth()
  const location = useLocation()
  const navigate = useNavigate()

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#030712]">
        <div className="flex flex-col items-center gap-4">
          <div className="w-10 h-10 border-2 border-emerald-500/30 border-t-emerald-400 rounded-full animate-spin" />
          <span className="text-xs font-mono text-slate-500 uppercase tracking-widest">
            Verifying CEO access
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
      <div className="min-h-screen flex flex-col items-center justify-center bg-[#030712] text-slate-200 px-6">
        <h1 className="text-xl font-semibold text-red-400 mb-2">Access denied</h1>
        <p className="text-sm text-slate-400 text-center max-w-md mb-6">
          CEO Command Center requires JWT role <span className="text-slate-300">ceo</span> or{' '}
          <span className="text-slate-300">is_superadmin</span> on your account. If an admin just
          upgraded you, sign in again so your cookies get a fresh token.
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
            Sign in again
          </button>
          <Link
            to="/operations"
            className="text-sm font-mono text-cyan-400 hover:text-cyan-300 underline underline-offset-4"
          >
            Open operator cockpit
          </Link>
        </div>
      </div>
    )
  }

  return children
}
