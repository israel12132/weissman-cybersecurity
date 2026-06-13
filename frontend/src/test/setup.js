// Extends Vitest's `expect` with @testing-library/jest-dom matchers
// (toBeInTheDocument, toHaveTextContent, ...). Imported via vitest.config.js
// `setupFiles`, so every test file gets the matchers without importing them.
import '@testing-library/jest-dom/vitest'
