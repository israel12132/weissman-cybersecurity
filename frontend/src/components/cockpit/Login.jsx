import { useCallback, useEffect } from 'react'
import { useLocation, useNavigate } from 'react-router'
import { useAuth } from '../../context/AuthContext'
import LanguageSwitcher from '../LanguageSwitcher'
import LoginGate from '../../auth/LoginGate'
import { resolvePostLoginHref } from '../../auth/loginNext'

export default function Login() {
  const { login, verifyMfa, isAuthenticated, isCeo } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()

  const onSuccess = useCallback(
    (result) => {
      const from = location.state?.from
      const fromPath = from ? `${from.pathname || ''}${from.search || ''}` : ''
      const href = resolvePostLoginHref(result, fromPath || undefined)
      const ccPrefix = '/command-center'
      const relative = href.startsWith(ccPrefix) ? href.slice(ccPrefix.length) || '/' : href
      navigate(relative.startsWith('/') ? relative : `/${relative}`, { replace: true })
    },
    [location.state, navigate],
  )

  useEffect(() => {
    if (isAuthenticated) {
      navigate(isCeo ? '/' : '/operations', { replace: true })
    }
  }, [isAuthenticated, isCeo, navigate])

  return (
    <LoginGate
      login={login}
      verifyMfa={verifyMfa}
      isAuthenticated={isAuthenticated}
      onSuccess={onSuccess}
      languageSwitcher={<LanguageSwitcher className="opacity-80 hover:opacity-100 transition-opacity" />}
      homeHref="/"
      signupHref="/signup"
      statusHref="/status"
    />
  )
}
