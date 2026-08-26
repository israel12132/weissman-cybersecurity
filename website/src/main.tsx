import { StrictMode, type ReactElement } from 'react'
import { createRoot } from 'react-dom/client'
import { LocaleProvider } from './i18n'
import { pageIdFromDocument } from './lib/pageFromPath'
import { HomePage } from './pages/HomePage'
import { PlatformPage } from './pages/PlatformPage'
import { ProductCapabilityPage } from './pages/ProductCapabilityPage'
import { SolutionsPage } from './pages/SolutionsPage'
import { TechnologyPage } from './pages/TechnologyPage'
import { ResourcesPage } from './pages/ResourcesPage'
import { AboutPage } from './pages/AboutPage'
import { ContactPage } from './pages/ContactPage'
import { PricingPage } from './pages/PricingPage'
import { SignupPage } from './pages/SignupPage'
import { LegalPage } from './pages/LegalPage'
import { NotFoundPage } from './pages/NotFoundPage'
import './styles/index.css'

const pages: Record<string, () => ReactElement> = {
  home: () => <HomePage />,
  platform: () => <PlatformPage />,
  'endpoint-protection': () => <ProductCapabilityPage productId="endpoint-protection" />,
  'vulnerability-research': () => <ProductCapabilityPage productId="vulnerability-research" />,
  'detection-response': () => <ProductCapabilityPage productId="detection-response" />,
  'attack-path-intelligence': () => <ProductCapabilityPage productId="attack-path-intelligence" />,
  'private-ai': () => <ProductCapabilityPage productId="private-ai" />,
  'security-operations': () => <ProductCapabilityPage productId="security-operations" />,
  'oast-validation': () => <ProductCapabilityPage productId="oast-validation" />,
  solutions: () => <SolutionsPage />,
  technology: () => <TechnologyPage />,
  resources: () => <ResourcesPage />,
  about: () => <AboutPage />,
  contact: () => <ContactPage />,
  pricing: () => <PricingPage />,
  signup: () => <SignupPage />,
  terms: () => <LegalPage doc="terms" />,
  privacy: () => <LegalPage doc="privacy" />,
  'terms-he': () => <LegalPage doc="terms-he" />,
  'privacy-he': () => <LegalPage doc="privacy-he" />,
  dpa: () => <LegalPage doc="dpa" />,
  subprocessors: () => <LegalPage doc="subprocessors" />,
  'security-policy': () => <LegalPage doc="security-policy" />,
  'not-found': () => <NotFoundPage />,
}

const id = pageIdFromDocument()
const Page = pages[id] ?? pages['not-found']
const root = document.getElementById('root')
if (!root) throw new Error('root missing')
createRoot(root).render(
  <StrictMode>
    <LocaleProvider>{Page()}</LocaleProvider>
  </StrictMode>,
)
