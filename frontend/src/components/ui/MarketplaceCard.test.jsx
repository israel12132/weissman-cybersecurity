import { describe, it, expect, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import MarketplaceCard from './MarketplaceCard.jsx'

afterEach(cleanup)

describe('MarketplaceCard', () => {
  it('renders name, description, category and price', () => {
    render(
      <MarketplaceCard
        name="Dark Web Monitor"
        description="Continuous infostealer + credential-leak surveillance."
        category="Threat Intel"
        price="$49/mo"
      />,
    )
    expect(screen.getByText('Dark Web Monitor')).toBeInTheDocument()
    expect(screen.getByText(/infostealer/)).toBeInTheDocument()
    expect(screen.getByText('Threat Intel')).toBeInTheDocument()
    expect(screen.getByText('$49/mo')).toBeInTheDocument()
  })

  it('fires onInstall from the install button', () => {
    const onInstall = vi.fn()
    render(<MarketplaceCard name="X" description="d" onInstall={onInstall} />)
    fireEvent.click(screen.getByRole('button', { name: /Install/i }))
    expect(onInstall).toHaveBeenCalled()
  })

  it('shows a disabled Installed state when installed', () => {
    render(<MarketplaceCard name="X" description="d" installed />)
    const btn = screen.getByRole('button', { name: /Installed/i })
    expect(btn).toBeDisabled()
  })

  it('exposes an accessible rating label', () => {
    render(<MarketplaceCard name="X" description="d" rating={4} />)
    expect(screen.getByLabelText('Rating 4 of 5')).toBeInTheDocument()
  })

  it('opens details via onOpen when the title is activated', () => {
    const onOpen = vi.fn()
    render(<MarketplaceCard name="Engine" description="d" onOpen={onOpen} />)
    fireEvent.click(screen.getByRole('button', { name: 'Engine' }))
    expect(onOpen).toHaveBeenCalled()
  })
})
