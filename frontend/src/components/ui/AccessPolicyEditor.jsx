import { forwardRef } from 'react'
import { Plus, Trash2 } from 'lucide-react'
import { cn } from '../../lib/cn'
import Select from './Select.jsx'
import Input from './Input.jsx'
import Button from './Button.jsx'

const EFFECT_STYLE = {
  allow: 'text-status-active',
  deny: 'text-severity-critical',
}

/**
 * AccessPolicyEditor — a controlled rule builder for RBAC/ABAC policies. Each
 * rule is { id, effect: 'allow'|'deny', subject, action, resource, condition }.
 * Presentational: edits are reported via onChange(nextRules); persist server-side.
 *
 * @param {Array<object>} rules @param {(rules:Array<object>)=>void} onChange
 * @param {Array<{value,label}>} [subjects] @param {Array<{value,label}>} [actions]
 * @param {Array<{value,label}>} [resources]
 */
const AccessPolicyEditor = forwardRef(function AccessPolicyEditor(
  {
    rules = [],
    onChange,
    subjects = [],
    actions = [],
    resources = [],
    className,
    ...props
  },
  ref,
) {
  const patch = (id, key, value) =>
    onChange?.(rules.map((r) => (r.id === id ? { ...r, [key]: value } : r)))

  const remove = (id) => onChange?.(rules.filter((r) => r.id !== id))

  const add = () => {
    // Deterministic id from the current max index (no Date.now/random).
    const nextId = `rule-${rules.length + 1}-${rules.reduce((m, r) => Math.max(m, Number(String(r.id).split('-').pop()) || 0), 0) + 1}`
    onChange?.([
      ...rules,
      { id: nextId, effect: 'allow', subject: '', action: '', resource: '', condition: '' },
    ])
  }

  return (
    <div ref={ref} className={cn('flex flex-col gap-3', className)} {...props}>
      <ul className="flex flex-col gap-2">
        {rules.map((rule) => (
          <li
            key={rule.id}
            className="flex flex-wrap items-end gap-2 rounded-xl border border-border-default bg-bg-2 p-3"
          >
            <div className="w-28">
              <Select
                aria-label="Effect"
                value={rule.effect}
                onChange={(e) => patch(rule.id, 'effect', e.target.value)}
                options={[
                  { value: 'allow', label: 'Allow' },
                  { value: 'deny', label: 'Deny' },
                ]}
                className={cn('font-medium', EFFECT_STYLE[rule.effect])}
              />
            </div>
            <div className="min-w-[8rem] flex-1">
              <Select
                aria-label="Subject"
                value={rule.subject}
                onChange={(e) => patch(rule.id, 'subject', e.target.value)}
                placeholder="Subject (role/attr)"
                options={subjects}
              />
            </div>
            <div className="min-w-[8rem] flex-1">
              <Select
                aria-label="Action"
                value={rule.action}
                onChange={(e) => patch(rule.id, 'action', e.target.value)}
                placeholder="Action"
                options={actions}
              />
            </div>
            <div className="min-w-[8rem] flex-1">
              <Select
                aria-label="Resource"
                value={rule.resource}
                onChange={(e) => patch(rule.id, 'resource', e.target.value)}
                placeholder="Resource"
                options={resources}
              />
            </div>
            <div className="min-w-[10rem] flex-1">
              <Input
                aria-label="Condition"
                value={rule.condition ?? ''}
                onChange={(e) => patch(rule.id, 'condition', e.target.value)}
                placeholder="Condition (e.g. env == 'prod')"
              />
            </div>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => remove(rule.id)}
              aria-label="Remove rule"
              leftIcon={<Trash2 />}
            />
          </li>
        ))}
      </ul>
      {rules.length === 0 && (
        <p className="text-xs text-text-muted">No rules yet — every request is denied by default.</p>
      )}
      <div>
        <Button variant="secondary" size="sm" leftIcon={<Plus />} onClick={add}>
          Add rule
        </Button>
      </div>
    </div>
  )
})

AccessPolicyEditor.displayName = 'AccessPolicyEditor'

export default AccessPolicyEditor
export { AccessPolicyEditor }
