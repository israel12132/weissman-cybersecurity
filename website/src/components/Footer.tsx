import { company } from '../content/site'
import { footerNav } from '../content/nav'
import { useI18n } from '../i18n'
import { A } from './A'
import { Ltr } from './Ltr'

export function Footer() {
  const { t, n } = useI18n()
  const year = n(new Date().getFullYear())
  return (
    <footer className="border-t border-[var(--line)] pb-10 pt-16 text-sm text-muted">
      <div className="site-wrap grid gap-10 md:grid-cols-2 lg:grid-cols-5">
        <div>
          <p className="font-brand text-xs tracking-[0.22em] text-ink">WEISSMAN</p>
          <p className="mt-3 max-w-xs leading-relaxed">
            {t('brand.legalName')}
            <br />
            {t('brand.location')}
          </p>
          <p className="mt-4">
            <a className="text-accent hover:underline" href={`mailto:${company.emails.sales}`}>
              <Ltr>{company.emails.sales}</Ltr>
            </a>
          </p>
        </div>
        <NavCol title={t('nav.footer.product')} links={footerNav.product} />
        <NavCol title={t('nav.footer.company')} links={footerNav.company} />
        <NavCol title={t('nav.footer.resources')} links={footerNav.resources} />
        <NavCol title={t('nav.footer.legal')} links={footerNav.legal} />
      </div>
      <div className="site-wrap mt-12 flex flex-wrap justify-between gap-3 border-t border-[var(--line)] pt-6 text-xs text-dim">
        <span>
          © {year} {t('brand.legalName')}
        </span>
        <span>
          <a className="hover:text-accent" href={company.github}>
            {t('cta.github')}
          </a>
          {' · '}
          <A className="hover:text-accent" href="/privacy.html">
            {t('nav.footer.privacy')}
          </A>
          {' · '}
          <A className="hover:text-accent" href="/terms.html">
            {t('nav.footer.terms')}
          </A>
        </span>
      </div>
    </footer>
  )
}

function NavCol({ title, links }: { title: string; links: { id: string; href: string }[] }) {
  const { t } = useI18n()
  return (
    <div>
      <h2 className="mb-3 text-[0.7rem] font-semibold uppercase tracking-[0.16em] text-ink">{title}</h2>
      <ul className="space-y-2">
        {links.map((l) => (
          <li key={l.href + l.id}>
            <A className="hover:text-accent" href={l.href}>
              {t(`nav.footer.${l.id}`)}
            </A>
          </li>
        ))}
      </ul>
    </div>
  )
}
