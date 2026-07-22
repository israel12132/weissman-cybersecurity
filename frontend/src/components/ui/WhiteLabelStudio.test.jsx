import { describe, it, expect, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import WhiteLabelStudio from './WhiteLabelStudio.jsx'

afterEach(cleanup)

describe('WhiteLabelStudio', () => {
  it('reports brand name edits via onChange', () => {
    const onChange = vi.fn()
    render(<WhiteLabelStudio brand={{}} onChange={onChange} />)
    fireEvent.change(screen.getByLabelText('Brand name'), { target: { value: 'Acme' } })
    expect(onChange).toHaveBeenCalledWith({ name: 'Acme' })
  })

  it('reports palette edits via onChange', () => {
    const onChange = vi.fn()
    render(<WhiteLabelStudio brand={{}} onChange={onChange} />)
    fireEvent.change(screen.getByLabelText('Primary color'), { target: { value: '#ff0088' } })
    expect(onChange).toHaveBeenCalledWith({ primary: '#ff0088' })
  })

  it('renders the brand name in the live preview', () => {
    render(<WhiteLabelStudio brand={{ name: 'Contoso' }} onChange={() => {}} />)
    expect(screen.getByText('Contoso')).toBeInTheDocument()
  })

  it('calls onReset from the reset button', () => {
    const onReset = vi.fn()
    render(<WhiteLabelStudio brand={{ primary: '#fff' }} onChange={() => {}} onReset={onReset} />)
    fireEvent.click(screen.getByRole('button', { name: /Reset to default palette/i }))
    expect(onReset).toHaveBeenCalled()
  })
})
