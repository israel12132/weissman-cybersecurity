import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import { ThemeProvider, useTheme } from './ThemeContext'

function Probe() {
  const { theme, toggleTheme, setTheme } = useTheme()
  return (
    <div>
      <span data-testid="theme">{theme}</span>
      <button onClick={toggleTheme}>toggle</button>
      <button onClick={() => setTheme('light')}>light</button>
    </div>
  )
}

describe('ThemeProvider', () => {
  beforeEach(() => {
    localStorage.clear()
    document.documentElement.removeAttribute('data-theme')
  })
  afterEach(() => cleanup())

  it('defaults to dark and stamps data-theme on <html>', () => {
    render(
      <ThemeProvider>
        <Probe />
      </ThemeProvider>,
    )
    expect(screen.getByTestId('theme').textContent).toBe('dark')
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
  })

  it('toggles to light and persists to localStorage', () => {
    render(
      <ThemeProvider>
        <Probe />
      </ThemeProvider>,
    )
    fireEvent.click(screen.getByText('toggle'))
    expect(screen.getByTestId('theme').textContent).toBe('light')
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
    expect(localStorage.getItem('weissman_theme')).toBe('light')
  })

  it('restores the stored theme on mount', () => {
    localStorage.setItem('weissman_theme', 'light')
    render(
      <ThemeProvider>
        <Probe />
      </ThemeProvider>,
    )
    expect(screen.getByTestId('theme').textContent).toBe('light')
  })
})

function CycleProbe() {
  const { theme, cycleTheme, isHighContrast } = useTheme()
  return (
    <div>
      <span data-testid="theme">{theme}</span>
      <span data-testid="hc">{String(isHighContrast)}</span>
      <button onClick={cycleTheme}>cycle</button>
    </div>
  )
}

describe('ThemeProvider — high-contrast cycle', () => {
  beforeEach(() => {
    localStorage.clear()
    document.documentElement.removeAttribute('data-theme')
  })
  afterEach(() => cleanup())

  it('cycles dark → light → high-contrast → dark', () => {
    render(
      <ThemeProvider>
        <CycleProbe />
      </ThemeProvider>,
    )
    const theme = () => screen.getByTestId('theme').textContent
    expect(theme()).toBe('dark')
    fireEvent.click(screen.getByText('cycle'))
    expect(theme()).toBe('light')
    fireEvent.click(screen.getByText('cycle'))
    expect(theme()).toBe('high-contrast')
    expect(screen.getByTestId('hc').textContent).toBe('true')
    expect(document.documentElement.getAttribute('data-theme')).toBe('high-contrast')
    fireEvent.click(screen.getByText('cycle'))
    expect(theme()).toBe('dark')
  })

  it('restores a stored high-contrast theme on mount', () => {
    localStorage.setItem('weissman_theme', 'high-contrast')
    render(
      <ThemeProvider>
        <CycleProbe />
      </ThemeProvider>,
    )
    expect(screen.getByTestId('theme').textContent).toBe('high-contrast')
  })
})

function BrandProbe() {
  const { setBrand, clearBrand, brandName, logoUrl } = useTheme()
  return (
    <div>
      <span data-testid="brandName">{brandName || ''}</span>
      <span data-testid="logo">{logoUrl || ''}</span>
      <button onClick={() => setBrand({ primary: '#ff0088', name: 'Acme', logoUrl: '/acme.svg' })}>
        brand
      </button>
      <button onClick={clearBrand}>clear</button>
    </div>
  )
}

describe('ThemeProvider — white-label branding', () => {
  beforeEach(() => {
    localStorage.clear()
    document.documentElement.removeAttribute('style')
  })
  afterEach(() => cleanup())

  it('applies brand seeds as inline CSS vars and exposes logo/name', () => {
    render(
      <ThemeProvider>
        <BrandProbe />
      </ThemeProvider>,
    )
    fireEvent.click(screen.getByText('brand'))
    expect(document.documentElement.style.getPropertyValue('--brand-primary')).toBe('#ff0088')
    expect(screen.getByTestId('brandName').textContent).toBe('Acme')
    expect(screen.getByTestId('logo').textContent).toBe('/acme.svg')
    expect(localStorage.getItem('weissman_brand')).toContain('Acme')
  })

  it('clearBrand removes the inline overrides', () => {
    render(
      <ThemeProvider>
        <BrandProbe />
      </ThemeProvider>,
    )
    fireEvent.click(screen.getByText('brand'))
    fireEvent.click(screen.getByText('clear'))
    expect(document.documentElement.style.getPropertyValue('--brand-primary')).toBe('')
    expect(localStorage.getItem('weissman_brand')).toBe(null)
  })
})
