import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import Tabs, { TabList, Tab, TabPanel } from './Tabs.jsx'

function Sample(props) {
  return (
    <Tabs defaultValue="overview" {...props}>
      <TabList aria-label="Sections">
        <Tab value="overview">Overview</Tab>
        <Tab value="activity">Activity</Tab>
        <Tab value="settings" disabled>
          Settings
        </Tab>
      </TabList>
      <TabPanel value="overview">Overview content</TabPanel>
      <TabPanel value="activity">Activity content</TabPanel>
      <TabPanel value="settings">Settings content</TabPanel>
    </Tabs>
  )
}

afterEach(cleanup)

describe('Tabs', () => {
  it('renders a tablist with its tabs and shows the default panel', () => {
    render(<Sample />)
    expect(screen.getByRole('tablist', { name: 'Sections' })).toBeInTheDocument()
    expect(screen.getAllByRole('tab')).toHaveLength(3)
    // Only the active panel is exposed (inactive ones are `hidden`).
    const panel = screen.getByRole('tabpanel')
    expect(panel).toHaveTextContent('Overview content')
  })

  it('activates a tab on click, updating aria-selected and the visible panel', () => {
    render(<Sample />)
    const overview = screen.getByRole('tab', { name: 'Overview' })
    const activity = screen.getByRole('tab', { name: 'Activity' })
    expect(overview).toHaveAttribute('aria-selected', 'true')

    fireEvent.click(activity)

    expect(activity).toHaveAttribute('aria-selected', 'true')
    expect(overview).toHaveAttribute('aria-selected', 'false')
    expect(screen.getByRole('tabpanel')).toHaveTextContent('Activity content')
  })

  it('moves and activates the next tab with ArrowRight, with roving tabindex', () => {
    render(<Sample />)
    const overview = screen.getByRole('tab', { name: 'Overview' })
    const activity = screen.getByRole('tab', { name: 'Activity' })

    // Roving tabindex: active tab is the tab stop, others are removed.
    expect(overview).toHaveAttribute('tabindex', '0')
    expect(activity).toHaveAttribute('tabindex', '-1')

    overview.focus()
    fireEvent.keyDown(overview, { key: 'ArrowRight' })

    expect(activity).toHaveAttribute('aria-selected', 'true')
    expect(activity).toHaveAttribute('tabindex', '0')
    expect(overview).toHaveAttribute('tabindex', '-1')
  })

  it('associates each tab with its panel via aria-controls / aria-labelledby', () => {
    render(<Sample />)
    const overview = screen.getByRole('tab', { name: 'Overview' })
    const panel = screen.getByRole('tabpanel')
    expect(overview).toHaveAttribute('aria-controls', panel.getAttribute('id'))
    expect(panel).toHaveAttribute('aria-labelledby', overview.getAttribute('id'))
  })

  it('does not activate a disabled tab', () => {
    render(<Sample />)
    const overview = screen.getByRole('tab', { name: 'Overview' })
    const settings = screen.getByRole('tab', { name: 'Settings' })
    expect(settings).toBeDisabled()

    fireEvent.click(settings)

    expect(settings).toHaveAttribute('aria-selected', 'false')
    expect(overview).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('tabpanel')).toHaveTextContent('Overview content')
  })
})
