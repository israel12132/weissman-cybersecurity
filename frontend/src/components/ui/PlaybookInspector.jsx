import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Trash2 } from 'lucide-react'
import { cn } from '../../lib/cn'
import Button from './Button.jsx'
import {
  ACTION_KIND_CATALOG,
  SET_STATUS_OPTIONS,
  NODE_LABEL,
  kindMeta,
  isPersistableAction,
} from '../../lib/playbookFlow.js'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']
const SEV_COLORS = {
  critical: { bg: 'bg-rose-500/15', ring: 'ring-rose-500/40', text: 'text-rose-200' },
  high: { bg: 'bg-orange-500/15', ring: 'ring-orange-500/40', text: 'text-orange-200' },
  medium: { bg: 'bg-amber-500/15', ring: 'ring-amber-500/40', text: 'text-amber-200' },
  low: { bg: 'bg-sky-500/15', ring: 'ring-sky-500/40', text: 'text-sky-200' },
  info: { bg: 'bg-[var(--border-strong)]/15', ring: 'ring-[var(--border-strong)]/40', text: 'text-[var(--text-secondary)]' },
}

function FieldLabel({ htmlFor, children }) {
  return (
    <label htmlFor={htmlFor} className="block text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
      {children}
    </label>
  )
}

function ToggleChip({ active, onClick, children, accent = 'cyan' }) {
  const activeCls = accent === 'amber'
    ? 'bg-amber-500/15 ring-amber-400/35 text-amber-200'
    : 'bg-cyan-500/15 ring-cyan-400/35 text-cyan-200'
  return (
    <Button
      variant="unstyled"
      type="button"
      onClick={onClick}
      className={cn(
        'rounded-full px-3 py-1.5 text-[11px] font-medium ring-1 transition-all',
        active
          ? activeCls
          : 'bg-[var(--row-hover-bg)] ring-white/[0.08] text-[var(--text-muted)] hover:bg-[var(--row-hover-bg)] hover:text-[var(--text-secondary)]',
      )}
    >
      {children}
    </Button>
  )
}

/**
 * Trigger condition fields shared by the list editor and the canvas inspector.
 */
export function PlaybookTriggerFields({ trigger = {}, onChange, idPrefix = 'pb-trigger' }) {
  const { t } = useTranslation()
  const update = (patch) => onChange({ ...trigger, ...patch })
  const severity = trigger.severity || []

  return (
    <div className="space-y-4">
      <div>
        <p className="mb-2 text-[11px] text-[var(--text-muted)]">{t('playbooks.severity_any')}</p>
        <div className="flex flex-wrap gap-2">
          {SEVERITIES.map((s) => {
            const active = severity.includes(s)
            const colors = SEV_COLORS[s]
            return (
              <Button
                variant="unstyled"
                type="button"
                key={s}
                onClick={() => update({
                  severity: active ? severity.filter((x) => x !== s) : [...severity, s],
                })}
                className={cn(
                  'rounded-full px-3 py-1 text-[10px] font-semibold uppercase tracking-wider ring-1 transition-all',
                  active
                    ? `${colors.bg} ${colors.ring} ${colors.text}`
                    : 'bg-[var(--row-hover-bg)] ring-white/[0.08] text-[var(--text-muted)] hover:text-[var(--text-tertiary)]',
                )}
              >
                {t(`playbooks.severity.${s}`)}
              </Button>
            )
          })}
        </div>
      </div>
      <div className="flex flex-wrap gap-2">
        <ToggleChip
          active={!!trigger.kev}
          onClick={() => update({ kev: trigger.kev ? undefined : true })}
          accent="amber"
        >
          {t('playbooks.require_kev')}
        </ToggleChip>
        <ToggleChip
          active={!!trigger.exposed}
          onClick={() => update({ exposed: trigger.exposed ? undefined : true })}
        >
          {t('playbooks.require_exposed')}
        </ToggleChip>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <FieldLabel htmlFor={`${idPrefix}-epss`}>{t('playbooks.epss_min')}</FieldLabel>
          <input
            id={`${idPrefix}-epss`}
            type="number"
            min="0"
            max="1"
            step="0.05"
            value={trigger.epss_min ?? ''}
            onChange={(e) => update({
              epss_min: e.target.value === '' ? undefined : Number(e.target.value),
            })}
            className="mt-1 block w-full rounded-lg bg-[var(--bg-2)] px-3 py-2 text-[13px] text-[var(--text-primary)] ring-1 ring-white/[0.08] focus:outline-none focus:ring-cyan-400/30"
          />
        </div>
        <div>
          <FieldLabel htmlFor={`${idPrefix}-cooldown`}>{t('playbooks.cooldown')}</FieldLabel>
          <input
            id={`${idPrefix}-cooldown`}
            type="number"
            min="0"
            step="60"
            value={trigger.cooldown_seconds ?? ''}
            onChange={(e) => update({
              cooldown_seconds: e.target.value === '' ? undefined : Number(e.target.value),
            })}
            className="mt-1 block w-full rounded-lg bg-[var(--bg-2)] px-3 py-2 text-[13px] text-[var(--text-primary)] ring-1 ring-white/[0.08] focus:outline-none focus:ring-cyan-400/30"
          />
        </div>
      </div>
    </div>
  )
}

function ActionParamFields({ kind, params = {}, onChange, idPrefix }) {
  const { t } = useTranslation()
  const meta = ACTION_KIND_CATALOG.find((k) => k.kind === kind) || kindMeta(kind)
  const fields = meta.fields || []
  const patch = (key, value) => onChange({ ...params, [key]: value })

  return (
    <div className="space-y-3">
      {fields.map((field) => {
        const fid = `${idPrefix}-${field.key}`
        const label = t(`playbooks.field.${field.key}`)
        const value = params[field.key]
        if (field.input === 'select') {
          const options = field.options || SET_STATUS_OPTIONS
          return (
            <div key={field.key}>
              <FieldLabel htmlFor={fid}>{label}</FieldLabel>
              <select
                id={fid}
                value={value ?? options[0]}
                onChange={(e) => patch(field.key, e.target.value)}
                className="mt-1 block w-full rounded-lg bg-[var(--bg-2)] px-3 py-2 text-[13px] text-[var(--text-primary)] ring-1 ring-white/[0.08] focus:outline-none focus:ring-cyan-400/30"
              >
                {options.map((opt) => (
                  <option key={opt} value={opt}>{opt}</option>
                ))}
              </select>
            </div>
          )
        }
        if (field.input === 'textarea') {
          return (
            <div key={field.key}>
              <FieldLabel htmlFor={fid}>{label}</FieldLabel>
              <textarea
                id={fid}
                rows={3}
                value={value ?? ''}
                onChange={(e) => patch(field.key, e.target.value)}
                className="mt-1 block w-full resize-y rounded-lg bg-[var(--bg-2)] px-3 py-2 font-mono text-[12px] text-emerald-300/90 ring-1 ring-white/[0.08] focus:outline-none focus:ring-cyan-400/30"
              />
            </div>
          )
        }
        if (field.input === 'json') {
          return (
            <JsonParamField
              key={field.key}
              id={fid}
              label={label}
              value={value}
              onChange={(next) => patch(field.key, next)}
            />
          )
        }
        return (
          <div key={field.key}>
            <FieldLabel htmlFor={fid}>{label}</FieldLabel>
            <input
              id={fid}
              type={field.input === 'number' ? 'number' : 'text'}
              value={value ?? ''}
              onChange={(e) => patch(
                field.key,
                field.input === 'number'
                  ? (e.target.value === '' ? undefined : Number(e.target.value))
                  : e.target.value,
              )}
              className="mt-1 block w-full rounded-lg bg-[var(--bg-2)] px-3 py-2 text-[13px] text-[var(--text-primary)] ring-1 ring-white/[0.08] focus:outline-none focus:ring-cyan-400/30"
            />
          </div>
        )
      })}
    </div>
  )
}

function JsonParamField({ id, label, value, onChange }) {
  const { t } = useTranslation()
  const [text, setText] = useState(() => (typeof value === 'string' ? value : JSON.stringify(value ?? {}, null, 2)))
  const [invalid, setInvalid] = useState(false)

  useEffect(() => {
    if (typeof value !== 'string') setText(JSON.stringify(value ?? {}, null, 2))
  }, [value])

  return (
    <div>
      <FieldLabel htmlFor={id}>{label}</FieldLabel>
      <textarea
        id={id}
        rows={4}
        value={text}
        onChange={(e) => {
          setText(e.target.value)
          try {
            onChange(JSON.parse(e.target.value || '{}'))
            setInvalid(false)
          } catch {
            setInvalid(true)
          }
        }}
        className={cn(
          'mt-1 block w-full resize-y rounded-lg bg-[var(--bg-2)] px-3 py-2 font-mono text-[12px] text-emerald-300/90 ring-1 focus:outline-none',
          invalid ? 'ring-rose-500/40' : 'ring-white/[0.08] focus:ring-cyan-400/30',
        )}
        aria-invalid={invalid || undefined}
        aria-label={label}
      />
      <p className="mt-1 text-[10px] text-[var(--text-disabled)]">{t('playbooks.inspector.json_hint')}</p>
    </div>
  )
}

/**
 * Side inspector for the selected canvas node or edge.
 */
export default function PlaybookInspector({
  node,
  edge,
  onPatchNode,
  onDeleteNode,
  onDeleteEdge,
  className,
}) {
  const { t } = useTranslation()

  if (!node && !edge) {
    return (
      <aside className={cn('rounded-xl border border-border-default bg-bg-1/60 p-4 text-[12px] text-text-muted', className)}>
        <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-text-muted">
          {t('playbooks.inspector.title')}
        </h3>
        <p>{t('playbooks.inspector.no_selection')}</p>
      </aside>
    )
  }

  if (edge && !node) {
    return (
      <aside className={cn('rounded-xl border border-border-default bg-bg-1/60 p-4', className)}>
        <h3 className="mb-3 text-[10px] font-semibold uppercase tracking-[0.14em] text-text-muted">
          {t('playbooks.inspector.edge')}
        </h3>
        <p className="mb-3 font-mono text-[12px] text-text-secondary">
          {edge.source} → {edge.target}
        </p>
        <Button
          type="button"
          variant="danger"
          size="sm"
          leftIcon={<Trash2 />}
          onClick={() => onDeleteEdge?.(edge.id)}
        >
          {t('playbooks.inspector.delete_edge')}
        </Button>
      </aside>
    )
  }

  const kind = node.data?.kind
  const persistable = isPersistableAction(kind)
  const isTrigger = kind === 'trigger' || node.data?.nodeType === 'trigger'

  return (
    <aside className={cn('rounded-xl border border-border-default bg-bg-1/80 p-4', className)}>
      <div className="mb-3 flex items-start justify-between gap-2">
        <div>
          <h3 className="text-[10px] font-semibold uppercase tracking-[0.14em] text-text-muted">
            {t('playbooks.inspector.node')}
          </h3>
          <p className="mt-1 text-[13px] font-medium text-text-primary">
            {isTrigger ? t('playbooks.nodes.trigger') : t(persistable ? `playbooks.action.${kind}` : `playbooks.nodes.${node.data?.nodeType || 'action'}`)}
          </p>
        </div>
        {!isTrigger && (
          <Button
            type="button"
            variant="ghost"
            size="xs"
            leftIcon={<Trash2 />}
            onClick={() => onDeleteNode?.(node.id)}
            aria-label={t('playbooks.inspector.delete_node')}
          >
            {t('playbooks.inspector.delete_node')}
          </Button>
        )}
      </div>

      {isTrigger && (
        <PlaybookTriggerFields
          trigger={node.data?.trigger || {}}
          onChange={(next) => onPatchNode?.(node.id, { trigger: next })}
          idPrefix={`insp-${node.id}`}
        />
      )}

      {persistable && (
        <div className="space-y-3">
          <div>
            <FieldLabel htmlFor={`insp-${node.id}-kind`}>{t('playbooks.inspector.kind')}</FieldLabel>
            <select
              id={`insp-${node.id}-kind`}
              value={kind}
              onChange={(e) => {
                const next = e.target.value
                const meta = kindMeta(next)
                onPatchNode?.(node.id, {
                  kind: next,
                  nodeType: meta.nodeType,
                  params: { ...meta.defaultParams },
                  label: NODE_LABEL[meta.nodeType] || next,
                })
              }}
              className="mt-1 block w-full rounded-lg bg-[var(--bg-2)] px-3 py-2 text-[13px] text-[var(--text-primary)] ring-1 ring-white/[0.08] focus:outline-none focus:ring-cyan-400/30"
            >
              {ACTION_KIND_CATALOG.map((k) => (
                <option key={k.kind} value={k.kind}>{t(`playbooks.action.${k.kind}`)}</option>
              ))}
            </select>
          </div>
          <ActionParamFields
            kind={kind}
            params={node.data?.params || {}}
            onChange={(params) => onPatchNode?.(node.id, { params })}
            idPrefix={`insp-${node.id}`}
          />
        </div>
      )}

      {!isTrigger && !persistable && (
        <p className="text-[12px] text-amber-200/90">{t('playbooks.canvas.skipped_visual')}</p>
      )}
    </aside>
  )
}

export { PlaybookInspector, SEVERITIES }
