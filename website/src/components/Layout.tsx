import type { ReactNode } from 'react'
import { AnnouncementBar } from './AnnouncementBar'
import { CookieBanner } from './CookieBanner'
import { Footer } from './Footer'
import { JsonLd } from './JsonLd'
import { MegaNav } from './MegaNav'
import { SkipLink } from './SkipLink'

export function Layout({ children, announce = true }: { children: ReactNode; announce?: boolean }) {
  return (
    <>
      <SkipLink />
      {announce && <AnnouncementBar />}
      <MegaNav />
      <main id="main">{children}</main>
      <Footer />
      <CookieBanner />
      <JsonLd />
    </>
  )
}
