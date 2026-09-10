import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import Logo from '@cc/components/Logo'

export default function WwwFooter() {
  const { t } = useTranslation()
  return (
    <footer className="border-t border-white/10 bg-[#020617] px-5 py-12">
      <div className="mx-auto grid max-w-6xl gap-10 sm:grid-cols-2 lg:grid-cols-4">
        <div>
          <Logo size={32} />
          <p className="mt-4 max-w-xs text-sm text-white/45">{t('footer.tagline')}</p>
        </div>
        <div>
          <h2 className="text-[11px] font-semibold uppercase tracking-[0.16em] text-white/50">{t('footer.product')}</h2>
          <div className="mt-3 flex flex-col gap-2 text-sm text-white/70">
            <Link to="/platform">{t('nav.platform')}</Link>
            <Link to="/engines">{t('nav.engines')}</Link>
            <Link to="/pricing">{t('nav.pricing')}</Link>
            <a href="/login">{t('nav.sign_in')}</a>
          </div>
        </div>
        <div>
          <h2 className="text-[11px] font-semibold uppercase tracking-[0.16em] text-white/50">{t('footer.company')}</h2>
          <div className="mt-3 flex flex-col gap-2 text-sm text-white/70">
            <Link to="/company">{t('footer.about')}</Link>
            <Link to="/contact">{t('nav.contact')}</Link>
            <a href="/status">{t('footer.status')}</a>
          </div>
        </div>
        <div>
          <h2 className="text-[11px] font-semibold uppercase tracking-[0.16em] text-white/50">{t('footer.legal')}</h2>
          <div className="mt-3 flex flex-col gap-2 text-sm text-white/70">
            <a href="/terms.html">{t('footer.terms')}</a>
            <a href="/privacy.html">{t('footer.privacy')}</a>
            <a href="/dpa.html">{t('footer.dpa')}</a>
            <a href="/security-policy.html">{t('footer.disclosure')}</a>
          </div>
        </div>
      </div>
      <p className="mx-auto mt-10 max-w-6xl text-xs text-white/35">
        © {new Date().getFullYear()} {t('footer.copyright')}
      </p>
    </footer>
  )
}
