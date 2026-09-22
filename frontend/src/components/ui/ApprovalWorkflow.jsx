import { useTranslation } from 'react-i18next'
import { Check, X } from 'lucide-react'
import { cn } from '../../lib/cn'
import Stepper from './Stepper.jsx'
import Button from './Button.jsx'

const TO_STEP_STATUS = {
  approved: 'complete',
  pending: 'current',
  rejected: 'error',
  upcoming: 'upcoming',
}

/**
 * ApprovalWorkflow — a staged approval gate for playbook / change promotion.
 * Renders the approval chain as a stepper and exposes Approve/Reject actions for
 * the first pending stage. Controlled: handle onApprove / onReject and update the
 * stage statuses.
 *
 * @param {Array<{id:string,label:string,approver?:string,status?:'approved'|'pending'|'rejected'|'upcoming'}>} stages
 * @param {(stageId:string)=>void} [onApprove] @param {(stageId:string)=>void} [onReject]
 */
export default function ApprovalWorkflow({ stages = [], onApprove, onReject, className, ...props }) {
  const { t } = useTranslation()
  const pending = stages.find((s) => s.status === 'pending')

  const stepperSteps = stages.map((s) => ({
    id: s.id,
    label: s.label,
    description: s.approver,
    status: TO_STEP_STATUS[s.status] ?? 'upcoming',
  }))

  return (
    <div className={cn('flex flex-col gap-4', className)} {...props}>
      <Stepper steps={stepperSteps} />

      {pending ? (
        <div className="flex flex-wrap items-center gap-2 rounded-xl border border-border-default bg-bg-2 p-3">
          <span className="text-xs text-text-secondary">
            {t('components.approvalWorkflow.awaiting', 'Awaiting')}{' '}
            <span className="font-medium text-text-primary">{pending.label}</span>
            {pending.approver ? ` · ${pending.approver}` : ''}
          </span>
          <span className="ms-auto flex items-center gap-2">
            <Button size="sm" variant="danger" leftIcon={<X />} onClick={() => onReject?.(pending.id)}>
              {t('components.approvalWorkflow.reject', 'Reject')}
            </Button>
            <Button size="sm" leftIcon={<Check />} onClick={() => onApprove?.(pending.id)}>
              {t('components.approvalWorkflow.approve', 'Approve')}
            </Button>
          </span>
        </div>
      ) : (
        <p className="text-xs text-text-muted">
          {stages.some((s) => s.status === 'rejected')
            ? t('components.approvalWorkflow.rejected', 'Approval rejected.')
            : stages.length > 0
              ? t('components.approvalWorkflow.allComplete', 'All approvals complete.')
              : t('components.approvalWorkflow.noStages', 'No approval stages.')}
        </p>
      )}
    </div>
  )
}

export { ApprovalWorkflow }
