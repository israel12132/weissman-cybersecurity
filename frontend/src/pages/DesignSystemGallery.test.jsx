import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import { ThemeProvider } from '../context/ThemeContext'
import DesignSystemGallery from './DesignSystemGallery.jsx'

afterEach(cleanup)

/**
 * Smoke test — mounting the gallery exercises every primitive import and the
 * theme/brand controls, so a compile or render regression in any primitive (or
 * a broken export) fails here rather than silently at runtime.
 */
describe('DesignSystemGallery', () => {
  it('mounts and renders the header and section titles', () => {
    render(
      <ThemeProvider>
        <DesignSystemGallery />
      </ThemeProvider>,
    )
    expect(screen.getByText('Weissman Design System')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Button' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Overlays' })).toBeInTheDocument()
  })

  it('opens the Modal overlay from its trigger', () => {
    render(
      <ThemeProvider>
        <DesignSystemGallery />
      </ThemeProvider>,
    )
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Open modal/i }))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
  })
})
