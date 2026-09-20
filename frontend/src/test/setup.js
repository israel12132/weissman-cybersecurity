// Extends Vitest's `expect` with @testing-library/jest-dom matchers
// (toBeInTheDocument, toHaveTextContent, ...). Imported via vitest.config.js
// `setupFiles`, so every test file gets the matchers without importing them.
import '@testing-library/jest-dom/vitest'
import { afterEach } from 'vitest'
import { cleanup } from '@testing-library/react'

// `globals: false` (vitest.config.js) means @testing-library/react cannot
// auto-register its afterEach cleanup — so without this, every render() stays
// mounted for the remainder of the run. Any still-mounted component that
// schedules async React work (effects, transitions, the concurrent scheduler)
// can then flush AFTER a test file's jsdom environment has been torn down,
// throwing `ReferenceError: window is not defined` from react-dom's scheduler.
// Vitest reports that as an unhandled error and fails the whole `vitest run`
// with a non-zero exit even when every test passed. Unmounting after each test
// fires the components' effect cleanups (cancelling their timers / pending
// work) and drains the tree before teardown. cleanup() is idempotent, so this
// is safe alongside any test that also unmounts explicitly.
afterEach(() => {
  cleanup()
})
