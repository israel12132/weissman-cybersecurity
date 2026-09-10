import { Outlet, useLocation } from 'react-router'
import { useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import WwwNav from './WwwNav'
import WwwFooter from './WwwFooter'

const TITLES = {
  '/': 'meta.home',
  '/platform': 'meta.platform',
  '/engines': 'meta.engines',
  '/how-it-works': 'meta.how',
  '/pricing': 'meta.pricing',
  '/security': 'meta.security',
  '/contact': 'meta.contact',
  '/signup': 'meta.signup',
  '/company': 'meta.company',
}

export default function WwwShell() {
  const { t } = useTranslation()
  const { pathname } = useLocation()
  useEffect(() => {
    const key = Object.keys(TITLES).find((p) => pathname === p || (p !== '/' && pathname.startsWith(`${p}/`)))
    document.title = t(TITLES[key] || 'meta.home')
  }, [pathname, t])

  return (
    <div className="min-h-[100dvh] bg-[#030712] text-white">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:start-4 focus:top-4 focus:z-[60] focus:rounded-lg focus:bg-cyan-400 focus:px-3 focus:py-2 focus:text-[#041018]">
        {t('nav.skip')}
      </a>
      <WwwNav />
      <main id="main">
        <Outlet />
      </main>
      <WwwFooter />
    </div>
  )
}
