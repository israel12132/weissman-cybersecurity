import { Layout } from '../components/Layout'
import { ButtonLink } from '../components/Button'

export function NotFoundPage() {
  return (
    <Layout announce={false}>
      <div className="site-wrap py-24 text-center">
        <p className="eyebrow">404</p>
        <h1 className="display mt-3 text-4xl text-ink">This path is not a page.</h1>
        <p className="mx-auto mt-4 max-w-md text-muted">
          The public site returns a real 404 for unknown URLs so crawlers and monitors are not shown the homepage.
        </p>
        <div className="mt-8 flex justify-center gap-3">
          <ButtonLink href="/">Home</ButtonLink>
          <ButtonLink variant="ghost" href="/platform/">
            Platform
          </ButtonLink>
        </div>
      </div>
    </Layout>
  )
}
