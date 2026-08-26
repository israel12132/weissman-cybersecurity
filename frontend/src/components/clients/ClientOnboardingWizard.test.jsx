import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (k, opts) => {
      if (opts?.defaultValue) return opts.defaultValue
      return k
    },
    i18n: { language: 'en' },
  }),
  initReactI18next: { type: '3rdParty', init: () => {} },
  Trans: ({ children }) => children,
}))

vi.mock('../../utils/apiFetch', () => ({ apiFetch: vi.fn() }))
vi.mock('../../hooks/useEngineRequirements', async (importOriginal) => {
  const orig = await importOriginal()
  return {
    ...orig,
    useEngineRequirements: () => ({
      catalog: {
        modules: { baseline_asm: { label_en: 'Baseline ASM', label_he: 'ASM', requirements: [], engine_count: 1 } },
        requirements: {
          msa_acknowledged: { label_en: 'MSA', scope: 'client' },
          emergency_contact: { label_en: 'Emergency Contact', scope: 'client' },
          contact_email: { label_en: 'Email', scope: 'client' },
          scope_domains: { label_en: 'Domains', scope: 'client' },
        },
      },
      tenantStatus: { llm_configured: false, oast_configured: false },
      loading: false,
      error: '',
    }),
  }
})

import ClientOnboardingWizard from './ClientOnboardingWizard.jsx'

afterEach(cleanup)

describe('ClientOnboardingWizard — sector dropdown', () => {
  const onSubmit = vi.fn()

  function renderWizard() {
    return render(
      <MemoryRouter>
        <ClientOnboardingWizard onSubmit={onSubmit} submitting={false} error="" filterQuery="" />
      </MemoryRouter>,
    )
  }

  function advanceToBasicStep() {
    // Step 0 is the legal/MSA step; clicking Next without filling fields
    // will trigger validation, so we fill the required fields first.
    const msaCheckbox = screen.getByRole('checkbox', { hidden: true })
    fireEvent.click(msaCheckbox)

    const [nameInput, phoneInput] = screen.getAllByRole('textbox', { hidden: true })
    fireEvent.change(nameInput, { target: { value: 'Ops lead' } })
    fireEvent.change(phoneInput, { target: { value: '+972501234567' } })

    // Click Next to advance to step 1 (basic info)
    const nextBtn = screen.getByRole('button', { name: /next|הבא/i })
    fireEvent.click(nextBtn)
  }

  it('renders the sector dropdown on the basic-info step', () => {
    renderWizard()
    advanceToBasicStep()

    // The sector <select> element should be present
    const select = screen.getByRole('combobox')
    expect(select).toBeDefined()
  })

  it('sector defaults to empty string (unclassified)', () => {
    renderWizard()
    advanceToBasicStep()

    const select = screen.getByRole('combobox')
    expect(select.value).toBe('')
  })

  it('selecting a sector value updates the combobox', () => {
    renderWizard()
    advanceToBasicStep()

    const select = screen.getByRole('combobox')
    fireEvent.change(select, { target: { value: 'energy' } })
    expect(select.value).toBe('energy')
  })

  it('selecting government sector updates the combobox', () => {
    renderWizard()
    advanceToBasicStep()

    const select = screen.getByRole('combobox')
    fireEvent.change(select, { target: { value: 'government' } })
    expect(select.value).toBe('government')
  })

  it('empty-string option is rendered', () => {
    renderWizard()
    advanceToBasicStep()

    const select = screen.getByRole('combobox')
    const options = Array.from(select.options).map((o) => o.value)
    expect(options).toContain('')
  })

  it('all 11 sector options are rendered', () => {
    renderWizard()
    advanceToBasicStep()

    const select = screen.getByRole('combobox')
    const sectorValues = Array.from(select.options)
      .map((o) => o.value)
      .filter(Boolean)

    expect(sectorValues).toEqual([
      'government',
      'energy',
      'healthcare',
      'finance',
      'technology',
      'manufacturing',
      'retail',
      'education',
      'defense',
      'telecom',
      'other',
    ])
  })
})
