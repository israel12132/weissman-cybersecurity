import { DemoForm } from '../components/DemoForm'
import { Layout } from '../components/Layout'
import { company } from '../content/site'

export function ContactPage() {
  return (
    <Layout>
      <div className="site-wrap grid gap-12 py-16 lg:grid-cols-12">
        <div className="lg:col-span-5">
          <p className="eyebrow">Contact</p>
          <h1 className="display mt-3 text-4xl text-ink md:text-5xl">Book a demo</h1>
          <p className="mt-5 text-lg text-muted">
            Tell us about the environment you want to walk. If this deployment cannot send mail, the form will say so — it will not pretend the request landed.
          </p>
          <ul className="mt-8 space-y-2 text-sm text-muted">
            <li>
              Sales:{' '}
              <a className="text-accent" href={`mailto:${company.emails.sales}`}>
                {company.emails.sales}
              </a>
            </li>
            <li>
              Security:{' '}
              <a className="text-accent" href={`mailto:${company.emails.security}`}>
                {company.emails.security}
              </a>
            </li>
            <li>
              Support:{' '}
              <a className="text-accent" href={`mailto:${company.emails.support}`}>
                {company.emails.support}
              </a>
            </li>
          </ul>
        </div>
        <div className="lg:col-span-7">
          <DemoForm />
        </div>
      </div>
    </Layout>
  )
}
