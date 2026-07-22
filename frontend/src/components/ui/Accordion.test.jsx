import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import Accordion, {
  AccordionItem,
  AccordionTrigger,
  AccordionContent,
} from './Accordion.jsx'

afterEach(cleanup)

describe('Accordion', () => {
  it('renders an open panel with its trigger button and region', () => {
    render(
      <Accordion type="single" defaultValue="a">
        <AccordionItem value="a">
          <AccordionTrigger>Section A</AccordionTrigger>
          <AccordionContent>Panel A body</AccordionContent>
        </AccordionItem>
      </Accordion>,
    )
    const trigger = screen.getByRole('button', { name: 'Section A' })
    expect(trigger).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByRole('region')).toHaveTextContent('Panel A body')
  })

  it('opens a closed panel when its trigger is clicked', () => {
    render(
      <Accordion type="single">
        <AccordionItem value="a">
          <AccordionTrigger>Section A</AccordionTrigger>
          <AccordionContent>Panel A body</AccordionContent>
        </AccordionItem>
      </Accordion>,
    )
    const trigger = screen.getByRole('button', { name: 'Section A' })
    expect(trigger).toHaveAttribute('aria-expanded', 'false')
    // Closed content is hidden, so it is absent from the accessibility tree.
    expect(screen.queryByRole('region')).toBeNull()

    fireEvent.click(trigger)
    expect(trigger).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByRole('region')).toHaveTextContent('Panel A body')
  })

  it('wires the trigger and content together via aria-controls / aria-labelledby', () => {
    render(
      <Accordion type="single" defaultValue="a">
        <AccordionItem value="a">
          <AccordionTrigger>Section A</AccordionTrigger>
          <AccordionContent>Panel A body</AccordionContent>
        </AccordionItem>
      </Accordion>,
    )
    const trigger = screen.getByRole('button', { name: 'Section A' })
    const region = screen.getByRole('region')
    expect(trigger.getAttribute('aria-controls')).toBe(region.getAttribute('id'))
    expect(region.getAttribute('aria-labelledby')).toBe(trigger.getAttribute('id'))
  })

  it('collapses the open single panel when clicked (collapsible)', () => {
    render(
      <Accordion type="single" defaultValue="a" collapsible>
        <AccordionItem value="a">
          <AccordionTrigger>Section A</AccordionTrigger>
          <AccordionContent>Panel A body</AccordionContent>
        </AccordionItem>
      </Accordion>,
    )
    const trigger = screen.getByRole('button', { name: 'Section A' })
    expect(trigger).toHaveAttribute('aria-expanded', 'true')
    fireEvent.click(trigger)
    expect(trigger).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByRole('region')).toBeNull()
  })

  it('does not toggle a disabled item', () => {
    render(
      <Accordion type="single">
        <AccordionItem value="a" disabled>
          <AccordionTrigger>Section A</AccordionTrigger>
          <AccordionContent>Panel A body</AccordionContent>
        </AccordionItem>
      </Accordion>,
    )
    const trigger = screen.getByRole('button', { name: 'Section A' })
    expect(trigger).toBeDisabled()
    fireEvent.click(trigger)
    expect(trigger).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByRole('region')).toBeNull()
  })

  it('keeps several panels open at once when type is multiple', () => {
    render(
      <Accordion type="multiple" defaultValue={['a', 'b']}>
        <AccordionItem value="a">
          <AccordionTrigger>Section A</AccordionTrigger>
          <AccordionContent>Body A</AccordionContent>
        </AccordionItem>
        <AccordionItem value="b">
          <AccordionTrigger>Section B</AccordionTrigger>
          <AccordionContent>Body B</AccordionContent>
        </AccordionItem>
      </Accordion>,
    )
    expect(
      screen.getByRole('button', { name: 'Section A' }),
    ).toHaveAttribute('aria-expanded', 'true')
    expect(
      screen.getByRole('button', { name: 'Section B' }),
    ).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getAllByRole('region')).toHaveLength(2)
  })
})
