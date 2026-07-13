import { useTranslation } from 'react-i18next'
import { Fingerprint, FileCode, X } from 'lucide-react'
import CopyButton from '../components/ui/CopyButton'
import Button from '../components/ui/Button'

export default function ForensicEvidencePanel({ node, evidence = [], onClose }) {
  const { t } = useTranslation()
  if (!node) return null

  const meta = typeof node.metadata === 'object' ? node.metadata : {}
  const hash = node.provenance_sha256 || meta.provenance_sha256 || '—'

  return (
    <div className="battlespace-forensic absolute bottom-3 right-3 z-20 w-full max-w-lg pointer-events-auto">
      <div className="rounded-xl border border-rose-500/30 bg-black/85 backdrop-blur-xl shadow-2xl overflow-hidden">
        <div className="flex items-center justify-between px-4 py-2 border-b border-white/10 bg-rose-950/30">
          <div className="flex items-center gap-2 min-w-0">
            <Fingerprint className="w-4 h-4 text-rose-400 shrink-0" />
            <span className="text-[10px] font-mono uppercase tracking-widest text-rose-200/90 truncate">
              {t('battlespace.forensic_provenance')}
            </span>
          </div>
          <Button variant="unstyled" type="button" onClick={onClose} className="p-1 text-white/40 hover:text-white/80" aria-label="Close">
            <X className="w-4 h-4" />
          </Button>
        </div>

        <div className="p-4 space-y-3 max-h-[40vh] overflow-y-auto">
          <div>
            <p className="text-sm font-semibold text-white">{node.label || node.graph_key || node.id}</p>
            <p className="text-[10px] font-mono text-white/40">{node.node_type}</p>
          </div>

          <div className="rounded-lg border border-cyan-500/20 bg-cyan-950/20 px-3 py-2">
            <p className="text-[9px] font-mono uppercase tracking-wider text-cyan-300/60 mb-1">SHA-256 integrity</p>
            <div className="flex items-center gap-2">
              <code className="text-[10px] font-mono text-cyan-100/90 break-all flex-1">{hash}</code>
              {hash !== '—' && <CopyButton value={hash} size="sm" />}
            </div>
          </div>

          {meta.stack_trace || meta.pcap_ref ? (
            <div className="space-y-2">
              {meta.pcap_ref && (
                <div className="rounded-lg border border-amber-500/20 bg-amber-950/15 px-3 py-2">
                  <p className="text-[9px] font-mono text-amber-300/70 uppercase">PCAP ref</p>
                  <code className="text-[10px] text-amber-100/80 break-all">{String(meta.pcap_ref)}</code>
                </div>
              )}
              {meta.stack_trace && (
                <div className="rounded-lg border border-white/10 bg-black/40 px-3 py-2">
                  <p className="text-[9px] font-mono text-white/40 uppercase mb-1">Stack trace</p>
                  <pre className="text-[9px] font-mono text-white/65 whitespace-pre-wrap max-h-32 overflow-y-auto">{String(meta.stack_trace)}</pre>
                </div>
              )}
            </div>
          ) : null}

          {evidence.length > 0 && (
            <div>
              <p className="text-[9px] font-mono uppercase tracking-wider text-white/35 mb-2 flex items-center gap-1">
                <FileCode className="w-3 h-3" />
                {t('battlespace.linked_findings')} ({evidence.length})
              </p>
              <ul className="space-y-1.5">
                {evidence.slice(0, 12).map((f, i) => (
                  <li key={f.id || i} className="rounded border border-white/8 bg-white/[0.02] px-2 py-1.5">
                    <p className="text-[11px] text-white/75 truncate">{f.title || f.type || 'Finding'}</p>
                    <p className="text-[9px] font-mono text-rose-300/70">{f.severity}</p>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {node.is_shadow && (
            <p className="text-[10px] font-mono text-violet-300/80 border border-violet-500/25 rounded-lg px-3 py-2 bg-violet-950/20">
              {t('battlespace.shadow_node')}
            </p>
          )}
        </div>
      </div>
    </div>
  )
}
