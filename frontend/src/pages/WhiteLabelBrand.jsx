/**
 * Tenant white-label — persisted via GET/PUT /api/tenant/brand (not session CSS only).
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Palette } from 'lucide-react'
import PageShell from './PageShell'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ShellScanActions from '../components/engine/ShellScanActions'
import WhiteLabelStudio from '../components/ui/WhiteLabelStudio'
import Button from '../components/ui/Button'
import { useTheme } from '../context/ThemeContext'
import { apiFetch } from '../utils/apiFetch'
import { downloadCsv } from '../lib/exportFindingsCsv'
import { useToast } from '../components/ui/Toaster'

const NS = 'pages.whiteLabelBrand'

export default function WhiteLabelBrand() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const { brand, setBrand, clearBrand } = useTheme()
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [raw, setRaw] = useState({})

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const d = await apiFetch('/api/tenant/brand')
      if (d?.ok === false) throw new Error(d.detail || 'load failed')
      const b = d?.brand && typeof d.brand === 'object' ? d.brand : {}
      setRaw(b)
      if (Object.keys(b).length) setBrand(b)
    } catch (e) {
      setError(e.message || t(`${NS}.load_failed`))
    } finally {
      setLoading(false)
    }
  }, [setBrand, t])

  useEffect(() => { load() }, [load])

  const persist = useCallback(async () => {
    setSaving(true)
    try {
      const d = await apiFetch('/api/tenant/brand', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ brand: brand || {} }),
      })
      if (d?.ok === false) throw new Error(d.detail || 'save failed')
      toast.success(t(`${NS}.saved`))
      setRaw(d.brand || brand || {})
    } catch (e) {
      toast.error(e.message || t(`${NS}.save_failed`))
    } finally {
      setSaving(false)
    }
  }, [brand, t, toast])

  const rows = useMemo(() => {
    const entries = Object.entries(brand || raw || {})
    const q = searchQuery.trim().toLowerCase()
    return entries.filter(([k, v]) => `${k} ${v}`.toLowerCase().includes(q))
  }, [brand, raw, searchQuery])

  const exportCsv = useCallback(() => {
    downloadCsv(rows.map(([k, v]) => [k, String(v ?? '')]), ['key', 'value'], 'weissman-tenant-brand')
  }, [rows])

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      icon={<Palette />}
      actions={(
        <ShellScanActions
          onRefresh={load}
          onExport={exportCsv}
          refreshLoading={loading}
          exportDisabled={!rows.length}
        />
      )}
    >
      <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>
      {error && <p className="text-sm text-rose-300" role="alert">{error}</p>}
      <input
        type="search"
        value={searchQuery}
        onChange={(e) => setSearchQuery(e.target.value)}
        placeholder={t(`${NS}.search_placeholder`)}
        aria-label={t(`${NS}.search_placeholder`)}
        className="mb-4 w-full max-w-sm px-3 py-2 rounded-lg text-sm bg-black/40 border border-white/10 text-white"
      />
      <WhiteLabelStudio
        brand={brand}
        onChange={setBrand}
        onReset={() => {
          clearBrand()
          setRaw({})
        }}
      />
      <div className="mt-4 flex gap-2">
        <Button type="button" onClick={persist} disabled={saving}>
          {saving ? t(`${NS}.saving`) : t(`${NS}.save`)}
        </Button>
      </div>
    </PageShell>
  )
}
