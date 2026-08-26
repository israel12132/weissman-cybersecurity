import { company } from '../content/site'
import { footerNav } from '../content/nav'

export function Footer() {
  const year = new Date().getFullYear()
  return (
    <footer className="border-t border-[var(--line)] pb-10 pt-16 text-sm text-muted">
      <div className="site-wrap grid gap-10 md:grid-cols-2 lg:grid-cols-5">
        <div>
          <p className="font-brand text-xs tracking-[0.22em] text-ink">WEISSMAN</p>
          <p className="mt-3 max-w-xs leading-relaxed">
            {company.legalName}
            <br />
            {company.location}
          </p>
          <p className="mt-4">
            <a className="text-accent hover:underline" href={`mailto:${company.emails.sales}`}>
              {company.emails.sales}
            </a>
          </p>
        </div>
        <NavCol title="Product" links={footerNav.product} />
        <NavCol title="Company" links={footerNav.company} />
        <NavCol title="Resources" links={footerNav.resources} />
        <NavCol title="Legal" links={footerNav.legal} />
      </div>
      <div className="site-wrap mt-12 flex flex-wrap justify-between gap-3 border-t border-[var(--line)] pt-6 text-xs text-dim">
        <span>
          © {year} {company.legalName}
        </span>
        <span>
          <a className="hover:text-accent" href={company.github}>
            GitHub
          </a>
          {' · '}
          <a className="hover:text-accent" href="/privacy.html">
            Privacy
          </a>
          {' · '}
          <a className="hover:text-accent" href="/terms.html">
            Terms
          </a>
        </span>
      </div>
    </footer>
  )
}

function NavCol({ title, links }: { title: string; links: { label: string; href: string }[] }) {
  return (
    <div>
      <h2 className="mb-3 text-[0.7rem] font-semibold uppercase tracking-[0.16em] text-ink">{title}</h2>
      <ul className="space-y-2">
        {links.map((l) => (
          <li key={l.href + l.label}>
            <a className="hover:text-accent" href={l.href}>
              {l.label}
            </a>
          </li>
        ))}
      </ul>
    </div>
  )
}
