import { useState } from 'react'
import { Play, RotateCcw } from 'lucide-react'
import { cn } from '../../lib/cn'
import Stepper from './Stepper.jsx'
import Timeline from './Timeline.jsx'
import Button from './Button.jsx'

/**
 * DryRunSimulator — runs a sample event through a playbook's steps and shows the
 * resulting trace. Each step may provide `evaluate(sampleEvent)` returning a
 * boolean (pass/fail); steps without one always pass. Self-contained.
 *
 * @param {Array<{id?:string,label:string,description?:string,evaluate?:(e:any)=>boolean}>} steps
 * @param {any} [sampleEvent] @param {(trace:Array)=>void} [onComplete]
 */
export default function DryRunSimulator({ steps = [], sampleEvent, onComplete, className, ...props }) {
  const [statuses, setStatuses] = useState(() => steps.map(() => 'upcoming'))
  const [trace, setTrace] = useState([])
  const [ran, setRan] = useState(false)

  const run = () => {
    const nextStatuses = []
    const nextTrace = []
    let halted = false
    steps.forEach((step, i) => {
      if (halted) {
        nextStatuses.push('upcoming')
        return
      }
      let passed = true
      try {
        passed = typeof step.evaluate === 'function' ? Boolean(step.evaluate(sampleEvent)) : true
      } catch {
        passed = false
      }
      nextStatuses.push(passed ? 'complete' : 'error')
      nextTrace.push({
        id: step.id ?? i,
        title: step.label,
        description: passed ? 'Passed' : 'Failed — halted',
        variant: passed ? 'success' : 'danger',
        timestamp: `step ${i + 1}`,
      })
      if (!passed) halted = true
    })
    setStatuses(nextStatuses)
    setTrace(nextTrace)
    setRan(true)
    onComplete?.(nextTrace)
  }

  const reset = () => {
    setStatuses(steps.map(() => 'upcoming'))
    setTrace([])
    setRan(false)
  }

  const stepperSteps = steps.map((s, i) => ({
    id: s.id ?? i,
    label: s.label,
    description: s.description,
    status: statuses[i] ?? 'upcoming',
  }))

  return (
    <div className={cn('flex flex-col gap-4', className)} {...props}>
      <div className="flex items-center gap-2">
        <Button size="sm" leftIcon={<Play />} onClick={run} disabled={steps.length === 0}>
          Run dry-run
        </Button>
        {ran && (
          <Button size="sm" variant="ghost" leftIcon={<RotateCcw />} onClick={reset}>
            Reset
          </Button>
        )}
      </div>

      <Stepper steps={stepperSteps} />

      {trace.length > 0 && (
        <div>
          <p className="mb-2 text-[10px] uppercase tracking-widest text-text-muted">Execution trace</p>
          <Timeline items={trace} dense />
        </div>
      )}
    </div>
  )
}

export { DryRunSimulator }
