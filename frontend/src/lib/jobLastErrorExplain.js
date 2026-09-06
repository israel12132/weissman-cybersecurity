/** Explain operator-facing async job errors without inventing telemetry. */

const TENANT_FULL_SCAN_TIMEOUT =
  /job timed out after (\d+)s \(tenant_full_scan\)/

export function tenantFullScanTimeoutSecs(lastError) {
  if (typeof lastError !== 'string') return null
  const m = lastError.match(TENANT_FULL_SCAN_TIMEOUT)
  return m ? Number(m[1]) : null
}

export function isTenantFullScanTimeout(lastError) {
  return tenantFullScanTimeoutSecs(lastError) != null
}
