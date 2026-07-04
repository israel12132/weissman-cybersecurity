/**
 * Forensic Engine Reality Badge — WASM-verified, closed Shadow DOM isolated.
 *
 * Zero-trust terminal surface: capabilities manifest is verified in a Web Worker
 * via Rust/WASM before any badge text is rendered. Tamper events are explicit.
 */
import { useEffect, useMemo, useRef, useState } from 'react'
import { useEngineCapabilities } from '../lib/useEngineCapabilities'
import { REALITY_KIND_META } from '../lib/realityKindMeta'
import { mountForensicShadow, unmountForensicShadow, forensicBadgeHtml } from './forensicShadowHost'
import {
  fetchProvenanceVerifyKey,
  forensicWorkerRequest,
} from './forensicProvenanceClient'

/**
 * @typedef {'pending'|'verified'|'tamper'|'error'} ForensicState
 */

/**
 * @param {object} props
 * @param {string} [props.engineId]
 * @param {string} [props.kind]
 * @param {string} [props.canonical]
 * @param {boolean} [props.remoteDetection]
 * @param {'xs'|'sm'|'md'} [props.size]
 * @param {boolean} [props.showRemote]
 * @param {boolean} [props.showCanonical]
 * @param {string} [props.className]
 */
export default function ForensicEngineRealityBadge({
  engineId,
  kind: kindProp,
  canonical: canonicalProp,
  remoteDetection: remoteProp,
  size = 'xs',
  showRemote = false,
  showCanonical = false,
  className = '',
}) {
  const hostRef = useRef(null)
  const { byId, legend, loading, payload } = useEngineCapabilities()
  const [forensic, setForensic] = useState(/** @type {{ state: ForensicState, detail: string }} */({
    state: 'pending',
    detail: 'awaiting WASM provenance verification',
  }))

  const cap = engineId ? byId[engineId] : null
  const kind = kindProp ?? cap?.kind
  const canonical = canonicalProp ?? cap?.canonical
  const remoteDetection = remoteProp ?? cap?.remote_detection
  const meta = REALITY_KIND_META[kind]
  const legendHint = legend?.[kind]

  useEffect(() => {
    let cancelled = false

    async function verify() {
      if (!payload?.engines?.length) {
        if (!loading) {
          setForensic({ state: 'error', detail: 'capabilities manifest empty — cannot verify' })
        }
        return
      }
      const manifest = payload.provenance
      if (!manifest?.payload_sha256) {
        setForensic({
          state: 'tamper',
          detail: 'capabilities response missing cryptographic provenance manifest',
        })
        return
      }
      try {
        const { provenance, ...bodyWithoutProv } = payload
        const bodyJson = JSON.stringify(bodyWithoutProv)
        const manifestJson = JSON.stringify(manifest)
        const secret = await fetchProvenanceVerifyKey()
        const result = await forensicWorkerRequest('verify_capabilities', {
          bodyJson,
          manifestJson,
          secret,
        })
        if (cancelled) return
        if (result.status === 'verified') {
          setForensic({ state: 'verified', detail: result.detail || 'manifest verified' })
        } else {
          setForensic({
            state: 'tamper',
            detail: result.detail || 'FORENSIC TAMPER — provenance verification failed',
          })
        }
      } catch (err) {
        if (!cancelled) {
          setForensic({
            state: 'error',
            detail: err?.message || 'WASM provenance worker failure',
          })
        }
      }
    }

    verify()
    return () => {
      cancelled = true
    }
  }, [payload, loading])

  const shadowHtml = useMemo(() => {
    if (forensic.state === 'tamper') {
      return forensicBadgeHtml({
        label: 'FORENSIC TAMPER',
        tone: 'tamper',
        detail: forensic.detail,
      })
    }
    if (forensic.state === 'error') {
      return forensicBadgeHtml({
        label: 'PROVENANCE ERROR',
        tone: 'tamper',
        detail: forensic.detail,
      })
    }
    if (!meta) {
      if (loading && engineId) {
        return forensicBadgeHtml({ label: 'VERIFYING…', tone: 'pending' })
      }
      return ''
    }

    const parts = [
      forensicBadgeHtml({
        label: meta.label,
        tone: forensic.state === 'verified' ? 'verified' : 'pending',
        detail: [
          meta.description,
          canonical ? `Resolves to ${canonical}` : '',
          legendHint || '',
          forensic.detail,
        ]
          .filter(Boolean)
          .join(' · '),
      }),
    ]

    if (showRemote && remoteDetection != null) {
      parts.push(
        forensicBadgeHtml({
          label: remoteDetection ? 'REMOTE' : 'LOCAL',
          tone: forensic.state === 'verified' ? 'verified' : 'pending',
          detail: remoteDetection ? 'Detects remotely without an agent' : 'Not remotely detectable',
        }),
      )
    }

    if (kind === 'alias' && canonical) {
      parts.push(
        `<span class="forensic-meta" title="Same engine as ${canonical}">= ${canonical}</span>`,
      )
    }

    if (showCanonical && canonical && kind !== 'alias') {
      parts.push(`<span class="forensic-meta" title="Canonical: ${canonical}">→ ${canonical}</span>`)
    }

    if (forensic.state === 'verified') {
      parts.push(
        forensicBadgeHtml({
          label: 'WASM ✓',
          tone: 'verified',
          detail: 'Cryptographic manifest verified in isolated worker',
        }),
      )
    }

    return parts.join('')
  }, [
    forensic,
    meta,
    loading,
    engineId,
    kind,
    canonical,
    remoteDetection,
    showRemote,
    showCanonical,
    legendHint,
  ])

  useEffect(() => {
    const host = hostRef.current
    if (!host) return undefined
    mountForensicShadow(host, shadowHtml || forensicBadgeHtml({ label: '…', tone: 'pending' }))
    return () => {
      unmountForensicShadow(host)
    }
  }, [shadowHtml])

  return (
    <span
      ref={hostRef}
      className={className}
      data-forensic-engine-id={engineId || ''}
      data-forensic-state={forensic.state}
      data-forensic-size={size}
      role="status"
      aria-live="polite"
      aria-label={
        forensic.state === 'tamper'
          ? `Forensic tamper detected for engine ${engineId || 'unknown'}`
          : `Engine reality badge ${engineId || ''} ${meta?.label || ''}`
      }
    />
  )
}
