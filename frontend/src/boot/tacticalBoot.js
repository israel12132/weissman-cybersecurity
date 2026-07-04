import { bootstrapLocales } from '../i18n/localeLoader'
import { registerTacticalServiceWorker } from './registerTacticalSw'

/**
 * Zero-latency tactical boot sequence — locales + SW before React hydration.
 */
export async function bootstrapTacticalShell() {
  const [sw] = await Promise.all([
    registerTacticalServiceWorker(),
    bootstrapLocales(),
  ])
  return sw
}
