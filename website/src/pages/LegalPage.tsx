import { Layout } from '../components/Layout'
import terms from '../content/legal/terms.html?raw'
import privacy from '../content/legal/privacy.html?raw'
import termsHe from '../content/legal/terms-he.html?raw'
import privacyHe from '../content/legal/privacy-he.html?raw'
import dpa from '../content/legal/dpa.html?raw'
import subprocessors from '../content/legal/subprocessors.html?raw'
import security from '../content/legal/security-policy.html?raw'

const docs: Record<string, string> = {
  terms,
  privacy,
  'terms-he': termsHe,
  'privacy-he': privacyHe,
  dpa,
  subprocessors,
  'security-policy': security,
}

export function LegalPage({ doc }: { doc: string }) {
  const html = docs[doc]
  return (
    <Layout>
      <article className="legal-doc px-4 py-16" dangerouslySetInnerHTML={{ __html: html || '<p>Document missing.</p>' }} />
    </Layout>
  )
}
