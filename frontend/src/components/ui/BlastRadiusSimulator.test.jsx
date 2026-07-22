import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import BlastRadiusSimulator from './BlastRadiusSimulator.jsx'

afterEach(cleanup)

describe('BlastRadiusSimulator', () => {
  it('renders mitigation and likelihood controls', () => {
    render(<BlastRadiusSimulator baseSle={100000} baseAle={400000} />)
    expect(screen.getByLabelText(/Threat likelihood/)).toBeInTheDocument()
    expect(screen.getByText('0%')).toBeInTheDocument()
  })

  it('starts with zero savings at 0% mitigation and expected likelihood', () => {
    render(<BlastRadiusSimulator baseSle={100000} baseAle={400000} />)
    // savings = max(0, baseAle*1 - baseAle*1*1) = 0
    expect(screen.getByTestId('savings').textContent).toMatch(/\$0/)
  })

  it('recomputes savings when mitigation increases', () => {
    render(<BlastRadiusSimulator baseSle={100000} baseAle={400000} />)
    const before = screen.getByTestId('savings').textContent
    fireEvent.change(screen.getByLabelText(/Mitigation coverage/), { target: { value: '50' } })
    const after = screen.getByTestId('savings').textContent
    expect(after).not.toBe(before)
    // 50% mitigation on a 400k ALE => ~200k saved
    expect(screen.getByText('50%')).toBeInTheDocument()
  })

  it('updates the mitigation percentage readout', () => {
    render(<BlastRadiusSimulator baseSle={100000} baseAle={400000} />)
    fireEvent.change(screen.getByLabelText(/Mitigation coverage/), { target: { value: '75' } })
    expect(screen.getByText('75%')).toBeInTheDocument()
  })
})
