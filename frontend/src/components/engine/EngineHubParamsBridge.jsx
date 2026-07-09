import { useEffect } from 'react'
import { useEngineHub } from '../../context/EngineHubContext'
import { useClientIntegrations } from '../../hooks/useClientIntegrations'
import { useEngineScanParams } from '../../hooks/useEngineScanParams'
import EngineScanParamsPanel from './EngineScanParamsPanel'

/**
 * Syncs hub scan params from PageShell and renders compact collapsible panel.
 */
export default function EngineHubParamsBridge({ engineId, clientId, className = '' }) {
  const { setHubEngineId, setHubExtraParams } = useEngineHub()
  const { integrations } = useClientIntegrations(clientId)
  const { schema, extraParams, setParam } = useEngineScanParams(engineId, integrations)

  useEffect(() => {
    setHubEngineId(engineId || null)
    return () => setHubEngineId(null)
  }, [engineId, setHubEngineId])

  useEffect(() => {
    setHubExtraParams(extraParams)
  }, [extraParams, setHubExtraParams])

  useEffect(() => () => setHubExtraParams({}), [setHubExtraParams])

  if (!schema?.length) return null

  return (
    <EngineScanParamsPanel
      engineId={engineId}
      schema={schema}
      values={extraParams}
      onChange={setParam}
      clientId={clientId}
      collapsible
      defaultCollapsed
      className={className}
    />
  )
}
