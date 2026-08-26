import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'

// i18n keys render as-is so assertions name the key, not a translation that may change.
vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k }),
}))

let directoryState
vi.mock('../../hooks/useTenantDirectory', () => ({
  default: () => directoryState,
}))

import TenantSlugField from './TenantSlugField'

function directory(overrides = {}) {
  return {
    status: 'ready',
    tenants: [
      { slug: 'default', name: 'Weissman HQ' },
      { slug: 'acme-energy', name: 'Acme Energy' },
    ],
    defaultSlug: 'default',
    allowCustom: false,
    reload: vi.fn(),
    ...overrides,
  }
}

beforeEach(() => {
  directoryState = directory()
})
afterEach(() => cleanup())

describe('TenantSlugField', () => {
  it('renders a select of live workspaces instead of a free-text box', () => {
    render(<TenantSlugField value="default" onChange={vi.fn()} />)
    const select = screen.getByLabelText('auth.tenant_slug')
    expect(select.tagName).toBe('SELECT')
    expect(
      Array.from(select.options).map((option) => option.value),
    ).toEqual(['default', 'acme-energy'])
    expect(screen.getByText('Weissman HQ · default')).toBeInTheDocument()
  })

  it('labels an option with just the slug when the name adds nothing', () => {
    directoryState = directory({ tenants: [{ slug: 'default', name: 'default' }] })
    render(<TenantSlugField value="default" onChange={vi.fn()} />)
    expect(screen.getByRole('option', { name: 'default' })).toBeInTheDocument()
  })

  it('reports the chosen slug', () => {
    const onChange = vi.fn()
    render(<TenantSlugField value="default" onChange={onChange} />)
    fireEvent.change(screen.getByLabelText('auth.tenant_slug'), { target: { value: 'acme-energy' } })
    expect(onChange).toHaveBeenCalledWith('acme-energy')
  })

  it('adopts a real slug when the form default does not exist on this instance', async () => {
    const onChange = vi.fn()
    directoryState = directory({
      tenants: [{ slug: 'acme-energy', name: 'Acme Energy' }],
      defaultSlug: 'default',
    })
    render(<TenantSlugField value="default" onChange={onChange} />)
    await waitFor(() => expect(onChange).toHaveBeenCalledWith('acme-energy'))
  })

  it('leaves an already-valid slug alone', async () => {
    const onChange = vi.fn()
    render(<TenantSlugField value="acme-energy" onChange={onChange} />)
    await waitFor(() => expect(screen.getByLabelText('auth.tenant_slug')).toHaveValue('acme-energy'))
    expect(onChange).not.toHaveBeenCalled()
  })

  it('shows a disabled loading select while the directory is in flight', () => {
    directoryState = directory({ status: 'loading', tenants: [] })
    render(<TenantSlugField value="default" onChange={vi.fn()} />)
    const select = screen.getByLabelText('auth.tenant_slug')
    expect(select).toBeDisabled()
    expect(screen.getByRole('option', { name: 'auth.tenant_loading' })).toBeInTheDocument()
  })

  it('falls back to manual entry, with the reason, when the server withholds the list', () => {
    directoryState = directory({ status: 'restricted', tenants: [], allowCustom: true })
    render(<TenantSlugField value="default" onChange={vi.fn()} />)
    const field = screen.getByLabelText('auth.tenant_slug')
    expect(field.tagName).toBe('INPUT')
    expect(screen.getByText('auth.tenant_directory_restricted')).toBeInTheDocument()
  })

  it('falls back to manual entry with a retry when the directory call failed', () => {
    const reload = vi.fn()
    directoryState = directory({ status: 'error', tenants: [], allowCustom: true, reload })
    render(<TenantSlugField value="default" onChange={vi.fn()} />)
    expect(screen.getByLabelText('auth.tenant_slug').tagName).toBe('INPUT')
    expect(screen.getByText('auth.tenant_directory_unavailable')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /auth.tenant_retry/ }))
    expect(reload).toHaveBeenCalled()
  })

  it('still submits typed input in the fallback state', () => {
    const onChange = vi.fn()
    directoryState = directory({ status: 'error', tenants: [], allowCustom: true })
    render(<TenantSlugField value="" onChange={onChange} />)
    fireEvent.change(screen.getByLabelText('auth.tenant_slug'), { target: { value: 'ops-eu' } })
    expect(onChange).toHaveBeenCalledWith('ops-eu')
  })

  it('offers a custom option only when the list may be incomplete, and it switches to an input', () => {
    render(<TenantSlugField value="default" onChange={vi.fn()} />)
    expect(screen.queryByRole('option', { name: 'auth.tenant_option_custom' })).toBeNull()

    cleanup()
    directoryState = directory({ allowCustom: true })
    render(<TenantSlugField value="default" onChange={vi.fn()} />)
    const select = screen.getByLabelText('auth.tenant_slug')
    expect(screen.getByRole('option', { name: 'auth.tenant_option_custom' })).toBeInTheDocument()

    fireEvent.change(select, { target: { value: '__custom__' } })
    expect(screen.getByLabelText('auth.tenant_slug').tagName).toBe('INPUT')
    // The sentinel must never reach the login request.
    expect(screen.getByLabelText('auth.tenant_slug')).toHaveValue('default')
  })

  it('can go back to the list after choosing custom entry', () => {
    directoryState = directory({ allowCustom: true })
    render(<TenantSlugField value="default" onChange={vi.fn()} />)
    fireEvent.change(screen.getByLabelText('auth.tenant_slug'), { target: { value: '__custom__' } })
    fireEvent.click(screen.getByRole('button', { name: /auth.tenant_back_to_list/ }))
    expect(screen.getByLabelText('auth.tenant_slug').tagName).toBe('SELECT')
  })
})
