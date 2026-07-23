import { useCallback } from 'react'
import { useFindingsWorkbench } from './useFindingsWorkbench'
import { useEngineHistory } from './useEngineHistory'

/**
 * Combines findings workbench + engine history reload for Weissman engine hubs.
 * Parent owns findings state; call applyHistoryRun(result) after refreshFromHistory().
 */
export function useWeissmanEnginePage(engineId, findings, options = {}) {
  const { csvPrefix, haystackFn } = options
  const workbench = useFindingsWorkbench(findings, {
    csvPrefix: csvPrefix || `weissman-${engineId}`,
    haystackFn,
  })
  const history = useEngineHistory(engineId)

  // eslint-disable-next-line react-hooks/exhaustive-deps
  const refreshFromHistory = useCallback(async () => history.loadLastRun(), [history.loadLastRun])

  return {
    ...workbench,
    ...history,
    refreshFromHistory,
  }
}

/** Apply a history run payload to parent setters. */
export function applyHistoryFindings(run, setFindings, extras = {}) {
  if (!run) return false
  setFindings(run.findings || [])
  if (extras.setLastUpdated && run.completedAt) extras.setLastUpdated(run.completedAt)
  if (extras.setJobId && run.jobId) extras.setJobId(run.jobId)
  return true
}
