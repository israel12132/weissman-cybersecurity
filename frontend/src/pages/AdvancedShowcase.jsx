import { useState } from 'react'
import { Search, ShieldCheck } from 'lucide-react'
import { cn } from '../lib/cn'

import Button from '../components/ui/Button'
import AiCommandConsole from '../components/ui/AiCommandConsole'
import CommentThread from '../components/ui/CommentThread'
import PresenceStack from '../components/ui/PresenceStack'
import DashboardGrid from '../components/ui/DashboardGrid'
import Topology3D from '../components/ui/Topology3D'
import SwarmMap from '../components/ui/SwarmMap'
import ReplayControls from '../components/ui/ReplayControls'
import NodePalette from '../components/ui/NodePalette'
import DryRunSimulator from '../components/ui/DryRunSimulator'
import ApprovalWorkflow from '../components/ui/ApprovalWorkflow'
import PlaybookCanvas from '../components/ui/PlaybookCanvas'
import EvidenceVault from '../components/ui/EvidenceVault'
import PartnerPortal from '../components/ui/PartnerPortal'
import AuditTrailExport from '../components/ui/AuditTrailExport'
import AccessPolicyEditor from '../components/ui/AccessPolicyEditor'
import BlastRadiusSimulator from '../components/ui/BlastRadiusSimulator'
import FindingDrawerV2 from '../components/ui/FindingDrawerV2'

const SECTIONS = [
  { id: 'ai-console', label: 'AI Console' },
  { id: 'collab', label: 'Collaboration' },
  { id: 'dashboard', label: 'Dashboards' },
  { id: 'topology', label: '3D Topology' },
  { id: 'swarm', label: 'Swarm Map' },
  { id: 'replay', label: 'Replay' },
  { id: 'soar', label: 'SOAR Builder' },
  { id: 'blast', label: 'Blast Radius' },
  { id: 'vault', label: 'Evidence Vault' },
  { id: 'mssp', label: 'Partner Portal' },
  { id: 'audit', label: 'Audit Export' },
  { id: 'rbac', label: 'RBAC/ABAC' },
  { id: 'finding', label: 'Finding v2' },
]

function Section({ id, title, description, children }) {
  return (
    <section id={id} className="scroll-mt-20">
      <div className="mb-3">
        <h2 className="font-display text-xl font-semibold text-text-primary tracking-tight">{title}</h2>
        {description && <p className="mt-1 text-sm text-text-tertiary">{description}</p>}
      </div>
      <div className="rounded-2xl border border-border-default bg-bg-2 p-5">{children}</div>
    </section>
  )
}

function TableOfContents({ query, setQuery }) {
  const visible = SECTIONS.filter((s) => s.label.toLowerCase().includes(query.trim().toLowerCase()))
  return (
    <nav
      aria-label="Component sections"
      className="sticky top-0 z-sticky -mx-4 mb-6 border-b border-border-default bg-bg-overlay px-4 py-3 backdrop-blur-md"
    >
      <div className="mb-2 flex items-center gap-2">
        <Search className="size-4 text-text-muted" aria-hidden="true" />
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Filter components…"
          aria-label="Filter components"
          className="flex-1 bg-transparent text-sm text-text-primary outline-none placeholder:text-text-muted"
        />
      </div>
      <div className="flex flex-wrap gap-1.5">
        {visible.map((s) => (
          <a
            key={s.id}
            href={`#${s.id}`}
            className="rounded-full border border-border-default bg-bg-3 px-2.5 py-0.5 text-[11px] text-text-tertiary hover:border-border-strong hover:text-text-secondary"
          >
            {s.label}
          </a>
        ))}
      </div>
    </nav>
  )
}

export default function AdvancedShowcase() {
  const [query, setQuery] = useState('')
  const [messages, setMessages] = useState([
    { id: 'u1', role: 'user', content: 'Show critical findings on prod' },
    {
      id: 'a1',
      role: 'assistant',
      content: '7 critical findings on production. Launch containment?',
      actions: [{ id: 'run', label: 'Run containment playbook', intent: 'danger' }],
    },
  ])
  const [comments, setComments] = useState([
    { id: 1, author: { name: 'Ada' }, body: 'Confirmed exploit in staging', timestamp: '09:12' },
  ])
  const [widgets, setWidgets] = useState([
    { id: 'w1', title: 'Open findings', span: 1, node: <p className="text-sm text-text-secondary">142</p> },
    { id: 'w2', title: 'Posture', span: 1, node: <p className="text-sm text-text-secondary">82 / 100</p> },
    { id: 'w3', title: 'MTTR', span: 1, node: <p className="text-sm text-text-secondary">4.2h</p> },
  ])
  const [replay, setReplay] = useState({ value: 42, playing: false, speed: 1 })
  const [stages, setStages] = useState([
    { id: 'author', label: 'Author', approver: 'Ada', status: 'approved' },
    { id: 'lead', label: 'Team lead', approver: 'Grace', status: 'pending' },
    { id: 'ciso', label: 'CISO', approver: 'Alan', status: 'upcoming' },
  ])
  const [tenant, setTenant] = useState('acme')
  const [rules, setRules] = useState([
    { id: 'rule-1', effect: 'allow', subject: 'analyst', action: 'read', resource: 'findings', condition: '' },
  ])
  const [findingOpen, setFindingOpen] = useState(false)

  const advanceApproval = (id, approved) =>
    setStages((prev) => {
      const idx = prev.findIndex((s) => s.id === id)
      return prev.map((s, i) => {
        if (i === idx) return { ...s, status: approved ? 'approved' : 'rejected' }
        if (approved && i === idx + 1) return { ...s, status: 'pending' }
        return s
      })
    })

  return (
    <div className="mx-auto w-full max-w-5xl px-4 py-8 sm:px-6">
      <div className="mb-4 flex items-center justify-between gap-3">
        <div>
          <h1 className="font-display text-2xl font-semibold text-text-primary">Advanced Components</h1>
          <p className="text-sm text-text-muted">AI · WarRoom · SOAR · Enterprise — the acquisition-grade surface.</p>
        </div>
        <a href="/command-center/design-system" className="text-xs text-accent-cyan hover:underline">
          ← Core gallery
        </a>
      </div>

      <TableOfContents query={query} setQuery={setQuery} />

      <div className="flex flex-col gap-10">
        <Section id="ai-console" title="AI Command Console" description="Multi-turn, context-aware, voice, one-click execution.">
          <AiCommandConsole
            messages={messages}
            context={[{ label: 'Client: Acme' }, { label: 'Env: prod' }]}
            suggestions={[{ label: 'Top risks today' }, { label: 'Run full scan' }]}
            onSubmit={(text) =>
              setMessages((m) => [
                ...m,
                { id: `u${m.length}`, role: 'user', content: text },
                { id: `a${m.length}`, role: 'assistant', content: 'On it — routing to the relevant engines.' },
              ])
            }
          />
        </Section>

        <Section id="collab" title="Real-time collaboration" description="Presence + comments (wire to a realtime backend).">
          <div className="mb-3">
            <PresenceStack users={[{ id: 1, name: 'Ada' }, { id: 2, name: 'Grace' }, { id: 3, name: 'Alan' }]} />
          </div>
          <CommentThread comments={comments} onSubmit={(t) => setComments((c) => [...c, { id: c.length + 1, author: { name: 'You' }, body: t }])} />
        </Section>

        <Section id="dashboard" title="Personalized dashboard" description="Reorder + remove widgets (keyboard-accessible).">
          <DashboardGrid widgets={widgets} editable onReorder={setWidgets} onRemove={(id) => setWidgets((w) => w.filter((x) => x.id !== id))} />
        </Section>

        <Section id="topology" title="3D topology (Three.js)" description="WebGL force-sphere with an accessible node list.">
          <Topology3D
            nodes={[
              { id: 'gw', label: 'edge-gw', severity: 'info' },
              { id: 'web', label: 'prod-web-01', severity: 'critical' },
              { id: 'db', label: 'db-01', severity: 'high' },
              { id: 'app', label: 'app-02', severity: 'medium' },
            ]}
            links={[{ source: 'gw', target: 'web' }, { source: 'web', target: 'db' }, { source: 'web', target: 'app' }]}
          />
        </Section>

        <Section id="swarm" title="Global swarm map" description="Heat points + connection arcs.">
          <SwarmMap
            points={[
              { id: 'tlv', lat: 32, lon: 34.8, intensity: 0.9, label: 'Tel Aviv' },
              { id: 'nyc', lat: 40.7, lon: -74, intensity: 0.5, label: 'New York' },
              { id: 'sg', lat: 1.3, lon: 103.8, intensity: 0.7, label: 'Singapore' },
            ]}
            arcs={[{ from: { lat: 32, lon: 34.8 }, to: { lat: 40.7, lon: -74 } }]}
          />
        </Section>

        <Section id="replay" title="Replay controls">
          <ReplayControls
            value={replay.value}
            max={300}
            playing={replay.playing}
            speed={replay.speed}
            onSeek={(v) => setReplay((r) => ({ ...r, value: v }))}
            onTogglePlay={() => setReplay((r) => ({ ...r, playing: !r.playing }))}
            onSpeedChange={(s) => setReplay((r) => ({ ...r, speed: s }))}
          />
        </Section>

        <Section id="soar" title="SOAR playbook builder" description="Palette · @xyflow canvas · dry-run · approval.">
          <div className="grid gap-4 lg:grid-cols-2">
            <div>
              <p className="mb-2 text-[10px] uppercase tracking-widest text-text-muted">Palette</p>
              <NodePalette />
            </div>
            <div>
              <p className="mb-2 text-[10px] uppercase tracking-widest text-text-muted">Dry-run</p>
              <DryRunSimulator
                steps={[
                  { id: 's1', label: 'Match trigger' },
                  { id: 's2', label: 'Check KEV', evaluate: () => true },
                  { id: 's3', label: 'Isolate host' },
                ]}
                sampleEvent={{ kev: true }}
              />
            </div>
          </div>
          <div className="mt-4">
            <p className="mb-2 text-[10px] uppercase tracking-widest text-text-muted">Canvas (drag from palette)</p>
            <PlaybookCanvas
              initialNodes={[{ id: 'n0', type: 'playbook', position: { x: 40, y: 40 }, data: { label: 'Trigger', nodeType: 'trigger' } }]}
            />
          </div>
          <div className="mt-4">
            <p className="mb-2 text-[10px] uppercase tracking-widest text-text-muted">Approval</p>
            <ApprovalWorkflow stages={stages} onApprove={(id) => advanceApproval(id, true)} onReject={(id) => advanceApproval(id, false)} />
          </div>
        </Section>

        <Section id="blast" title="Financial blast radius — what-if">
          <BlastRadiusSimulator
            baseSle={125000}
            baseAle={480000}
            crownJewels={[
              { name: 'Customer PII store', value: 210000 },
              { name: 'Payments gateway', value: 160000 },
            ]}
          />
        </Section>

        <Section id="vault" title="Evidence Vault" description="Tamper-evident, hash-sealed artifacts.">
          <EvidenceVault
            items={[
              { id: '1', name: 'memory-dump.raw', hash: 'a'.repeat(64), sealedAt: '09:12', verified: true, size: '2.4 GB' },
              { id: '2', name: 'tampered.log', hash: 'b'.repeat(64), sealedAt: '09:20', verified: false, size: '12 KB' },
            ]}
            onVerify={() => {}}
            onDownload={() => {}}
          />
        </Section>

        <Section id="mssp" title="Partner Portal (MSSP)">
          <PartnerPortal
            tenants={[
              { id: 'acme', name: 'Acme Corp', clients: 12, openFindings: 43, posture: 82, status: 'active' },
              { id: 'globex', name: 'Globex', clients: 5, openFindings: 120, posture: 54, status: 'pending' },
              { id: 'initech', name: 'Initech', clients: 8, openFindings: 12, posture: 91, status: 'active' },
            ]}
            activeTenantId={tenant}
            onSelectTenant={(t) => setTenant(t.id)}
          />
        </Section>

        <Section id="audit" title="Audit-trail export">
          <AuditTrailExport
            entries={[
              { timestamp: 't1', actor: 'ada', action: 'login', target: 'console', result: 'success' },
              { timestamp: 't2', actor: 'grace', action: 'delete', target: 'finding:42', result: 'failure' },
            ]}
          />
        </Section>

        <Section id="rbac" title="RBAC / ABAC policy editor">
          <AccessPolicyEditor
            rules={rules}
            onChange={setRules}
            subjects={[{ value: 'analyst', label: 'Analyst' }, { value: 'admin', label: 'Admin' }]}
            actions={[{ value: 'read', label: 'Read' }, { value: 'write', label: 'Write' }]}
            resources={[{ value: 'findings', label: 'Findings' }, { value: 'engines', label: 'Engines' }]}
          />
        </Section>

        <Section id="finding" title="Finding Detail Drawer v2" description="A full feature composed from primitives.">
          <Button leftIcon={<ShieldCheck />} onClick={() => setFindingOpen(true)}>
            Open finding drawer
          </Button>
        </Section>
      </div>

      <FindingDrawerV2
        open={findingOpen}
        onClose={() => setFindingOpen(false)}
        finding={{ title: 'GlobalProtect RCE', severity: 'critical', kev: true, host: 'prod-web-01', cve: 'CVE-2024-3400' }}
        risk={{
          narrative: 'Internet-facing KEV RCE adjacent to the payments database.',
          likelihood: 'high',
          impact: 'high',
          factors: [{ label: 'Internet-facing', level: 'high' }, { label: 'KEV-listed', level: 'high' }],
          recommendation: 'Apply the vendor hotfix within 24h.',
        }}
        attackPath={[
          { id: 'a', label: 'Recon', status: 'done' },
          { id: 'b', label: 'Access', status: 'active' },
          { id: 'c', label: 'Exfil', status: 'blocked' },
        ]}
        timeline={[{ id: 1, title: 'Detected', timestamp: '09:12', variant: 'danger' }]}
        evidence={[{ id: 'e', kind: 'log', caption: 'Access log', content: 'GET /ssl-vpn' }]}
        comments={[{ id: 'c', author: { name: 'Ada' }, body: 'Confirmed' }]}
        viewers={[{ id: 'u', name: 'Grace' }, { id: 'r', name: 'Rob' }]}
      />
    </div>
  )
}
