import { describe, it, expect, vi, afterEach, beforeAll } from 'vitest'
import { render, cleanup } from '@testing-library/react'

// jsdom has no ResizeObserver; the terminal observes its container to size the list.
beforeAll(() => {
  globalThis.ResizeObserver ??= class {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
})

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k) => k, i18n: { language: 'en' } }),
}))

// Stand in for react-window's List and expose the imperative handle the way the
// real v2 List does, so we can assert which method the component reaches for.
const handle = { scrollToRow: vi.fn() }
vi.mock('react-window', () => ({
  List: ({ listRef, rowCount, rowComponent: Row }) => {
    if (listRef) listRef.current = handle
    return (
      <div data-testid="list">
        {Array.from({ length: rowCount }, (_, index) => (
          <Row key={index} index={index} style={{}} />
        ))}
      </div>
    )
  },
}))

import LiveIntelTerminal from './LiveIntelTerminal.jsx'

afterEach(() => {
  cleanup()
  handle.scrollToRow.mockReset()
})

const EVENTS = [
  { id: 1, target: 'a.example', severity: 'high', message: 'finding one', time: '12:00:00' },
  { id: 2, target: 'b.example', severity: 'critical', message: 'finding two', time: '12:00:01' },
]

describe('LiveIntelTerminal auto-scroll', () => {
  // react-window v2 renamed the imperative handle from scrollToItem(index, align)
  // to scrollToRow({ index, align }). The old call threw "scrollToItem is not a
  // function" the moment the first event arrived — precisely when the panel matters.
  it('uses the react-window v2 scrollToRow handle, not the removed scrollToItem', () => {
    render(<LiveIntelTerminal events={EVENTS} connectionStatus="online" />)
    expect(handle.scrollToRow).toHaveBeenCalledWith({ index: EVENTS.length - 1, align: 'end' })
    expect(handle.scrollToItem).toBeUndefined()
  })

  it('renders incoming events without throwing', () => {
    expect(() =>
      render(<LiveIntelTerminal events={EVENTS} connectionStatus="online" />),
    ).not.toThrow()
  })

  it('does not scroll when there are no events', () => {
    const { container } = render(<LiveIntelTerminal events={[]} connectionStatus="online" />)
    expect(handle.scrollToRow).not.toHaveBeenCalled()
    expect(container.textContent).toContain('idleOnline')
  })
})
