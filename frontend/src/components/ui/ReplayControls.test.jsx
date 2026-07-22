import { describe, it, expect, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import ReplayControls from './ReplayControls.jsx'

afterEach(cleanup)

describe('ReplayControls', () => {
  it('renders the play control and formatted time', () => {
    render(<ReplayControls value={65} max={300} onSeek={() => {}} onTogglePlay={() => {}} />)
    expect(screen.getByRole('button', { name: 'Play replay' })).toBeInTheDocument()
    expect(screen.getByText(/1:05/)).toBeInTheDocument()
  })

  it('toggles playback', () => {
    const onTogglePlay = vi.fn()
    render(<ReplayControls value={0} max={100} playing onSeek={() => {}} onTogglePlay={onTogglePlay} />)
    fireEvent.click(screen.getByRole('button', { name: 'Pause replay' }))
    expect(onTogglePlay).toHaveBeenCalled()
  })

  it('seeks via the slider and skip buttons', () => {
    const onSeek = vi.fn()
    render(<ReplayControls value={20} max={100} onSeek={onSeek} onTogglePlay={() => {}} />)
    fireEvent.change(screen.getByLabelText('Replay position'), { target: { value: '55' } })
    expect(onSeek).toHaveBeenCalledWith(55)
    fireEvent.click(screen.getByRole('button', { name: 'Skip to end' }))
    expect(onSeek).toHaveBeenCalledWith(100)
  })

  it('changes playback speed', () => {
    const onSpeedChange = vi.fn()
    render(<ReplayControls value={0} max={100} onSeek={() => {}} onTogglePlay={() => {}} onSpeedChange={onSpeedChange} />)
    fireEvent.change(screen.getByLabelText('Speed'), { target: { value: '2' } })
    expect(onSpeedChange).toHaveBeenCalledWith(2)
  })
})
