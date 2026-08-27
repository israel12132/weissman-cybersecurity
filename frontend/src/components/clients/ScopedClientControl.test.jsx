import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { I18nextProvider } from 'react-i18next'
import i18n from 'i18next'
import ScopedClientControl from './ScopedClientControl.jsx'

const authState = vi.hoisted(() => ({ session: null }))
const clientState = vi.hoisted(() => ({
  clients: [],
  selectedClientId: null,
  setSelectedClientId: vi.fn(),
}))

vi.mock('../../context/AuthContext.jsx', () => ({
  useAuthOptional: () => ({ session: authState.session }),
}))

vi.mock('../../context/ClientContext.jsx', () => ({
  useClient: () => clientState,
}))

const i18nInstance = i18n.createInstance()
void i18nInstance.init({
  lng: 'en',
  fallbackLng: 'en',
  resources: {
    en: {
      translation: {
        components: {
          scopedClient: {
            unbound: 'No bound customer',
            locked_hint: 'This account is locked to one customer.',
            locked: 'Locked',
            select: 'Select client',
            bound_aria: 'Bound customer: {{name}}',
          },
        },
      },
    },
  },
})

function renderControl(props = {}) {
  return render(
    <I18nextProvider i18n={i18nInstance}>
      <ScopedClientControl {...props} />
    </I18nextProvider>,
  )
}

describe('ScopedClientControl — client_picker_hidden never exposes a picker', () => {
  beforeEach(() => {
    authState.session = null
    clientState.clients = []
    clientState.selectedClientId = null
    clientState.setSelectedClientId = vi.fn()
  })

  it('does not render select[name=client_id] when the JWT hides the picker', () => {
    authState.session = {
      ok: true,
      role: 'client',
      assigned_client_id: 7,
      is_client_user: true,
      client_picker_hidden: true,
    }
    clientState.clients = [
      { id: 7, name: 'Acme' },
      { id: 8, name: 'Other Corp' },
    ]
    clientState.selectedClientId = 7
    const { container } = renderControl()
    expect(container.querySelector('select[name="client_id"]')).toBeNull()
    expect(screen.queryByRole('combobox')).toBeNull()
    expect(screen.getByText('Acme')).toBeTruthy()
    expect(screen.getByText('Locked')).toBeTruthy()
    expect(screen.getByLabelText('Bound customer: Acme')).toBeTruthy()
  })

  it('staff operators with two clients still get a named client_id select', () => {
    authState.session = {
      ok: true,
      role: 'operator',
      is_staff: true,
      client_picker_hidden: false,
    }
    clientState.clients = [
      { id: 1, name: 'Acme' },
      { id: 2, name: 'Beta' },
    ]
    const { container } = renderControl()
    expect(container.querySelector('select[name="client_id"]')).toBeTruthy()
  })
})
