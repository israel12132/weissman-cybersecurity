import { useState } from 'react'
import {
  Palette,
  Command,
  ShieldCheck,
  Rocket,
  Bell,
  Trash2,
  Search,
  Sparkles,
} from 'lucide-react'
import { useTheme } from '../context/ThemeContext'

import Button from '../components/ui/Button'
import Card from '../components/ui/Card'
import Input from '../components/ui/Input'
import Select from '../components/ui/Select'
import Badge from '../components/ui/Badge'
import Skeleton from '../components/ui/Skeleton'
import EmptyState from '../components/ui/EmptyState'

import Checkbox from '../components/ui/Checkbox'
import RadioGroup from '../components/ui/Radio'
import Switch from '../components/ui/Switch'
import Tabs, { TabList, Tab, TabPanel } from '../components/ui/Tabs'
import Accordion, {
  AccordionItem,
  AccordionTrigger,
  AccordionContent,
} from '../components/ui/Accordion'
import Modal, { ModalBody } from '../components/ui/Modal'
import Drawer from '../components/ui/Drawer'
import Tooltip from '../components/ui/Tooltip'
import Popover from '../components/ui/Popover'
import Alert from '../components/ui/Alert'
import Avatar, { AvatarGroup } from '../components/ui/Avatar'
import Progress from '../components/ui/Progress'
import Spinner from '../components/ui/Spinner'
import Sparkline from '../components/ui/Sparkline'
import KpiStrip from '../components/ui/KpiStrip'
import CommandBar from '../components/ui/CommandBar'
import SmartFilterBar from '../components/ui/SmartFilterBar'
import BlastRadius from '../components/ui/BlastRadius'
import MiniHeatmap from '../components/ui/MiniHeatmap'
import Timeline from '../components/ui/Timeline'
import KillChainPath from '../components/ui/KillChainPath'
import EvidenceGallery from '../components/ui/EvidenceGallery'
import Stepper from '../components/ui/Stepper'
import WhiteLabelStudio from '../components/ui/WhiteLabelStudio'
import ComplianceMatrix from '../components/ui/ComplianceMatrix'
import MarketplaceCard from '../components/ui/MarketplaceCard'
import UsageMeter from '../components/ui/UsageMeter'
import RiskExplanation from '../components/ui/RiskExplanation'
import PlaybookNode from '../components/ui/PlaybookNode'

/**
 * Design System Gallery — a living catalogue of every design-system primitive,
 * with interactive examples, a theme switcher (dark / light / high-contrast) and
 * a white-label brand playground. Serves as in-app documentation and a manual
 * QA surface for the token system and primitives. Route: /design-system.
 */

function Section({ id, title, description, children }) {
  return (
    <section id={id} className="scroll-mt-24">
      <div className="mb-4">
        <h2 className="font-display text-xl font-semibold text-text-primary tracking-tight">
          {title}
        </h2>
        {description && (
          <p className="mt-1 text-sm text-text-tertiary leading-relaxed">{description}</p>
        )}
      </div>
      <Card variant="bordered" className="flex flex-wrap items-start gap-6">
        {children}
      </Card>
    </section>
  )
}

function Field({ label, children }) {
  return (
    <div className="flex flex-col gap-2">
      {label && (
        <span className="text-[10px] uppercase tracking-widest text-text-muted">{label}</span>
      )}
      <div className="flex flex-wrap items-center gap-3">{children}</div>
    </div>
  )
}

function ThemeControls() {
  const { theme, setTheme, themes, brand, setBrand, clearBrand } = useTheme()
  return (
    <Card variant="elevated" className="w-full">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <span className="inline-flex size-9 items-center justify-center rounded-lg bg-accent-gradient text-text-inverse">
            <Palette className="size-4" aria-hidden="true" />
          </span>
          <div>
            <h1 className="font-display text-lg font-semibold text-text-primary">
              Weissman Design System
            </h1>
            <p className="text-xs text-text-muted">
              Primitives · tokens · theming · white-label
            </p>
            <a href="/command-center/design-system/advanced" className="text-xs text-accent-cyan hover:underline">
              Advanced components (AI · WarRoom · SOAR · Enterprise) →
            </a>
          </div>
        </div>

        <Field label="Theme">
          {themes.map((th) => (
            <Button
              key={th}
              size="sm"
              variant={theme === th ? 'primary' : 'secondary'}
              onClick={() => setTheme(th)}
            >
              {th}
            </Button>
          ))}
        </Field>

        <Field label="White-label brand">
          <label className="inline-flex items-center gap-2 text-xs text-text-secondary">
            Primary
            <input
              type="color"
              aria-label="Brand primary color"
              defaultValue="#22d3ee"
              onChange={(e) => setBrand({ primary: e.target.value })}
              className="size-7 cursor-pointer rounded-md border border-border-default bg-transparent"
            />
          </label>
          <label className="inline-flex items-center gap-2 text-xs text-text-secondary">
            Secondary
            <input
              type="color"
              aria-label="Brand secondary color"
              defaultValue="#8b5cf6"
              onChange={(e) => setBrand({ secondary: e.target.value })}
              className="size-7 cursor-pointer rounded-md border border-border-default bg-transparent"
            />
          </label>
          <Button size="sm" variant="ghost" onClick={clearBrand} disabled={!brand}>
            Reset
          </Button>
        </Field>
      </div>
    </Card>
  )
}

export default function DesignSystemGallery() {
  const { brand, setBrand, clearBrand } = useTheme()
  const [modalOpen, setModalOpen] = useState(false)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [drawerSide, setDrawerSide] = useState('end')
  const [checked, setChecked] = useState(true)
  const [radio, setRadio] = useState('balanced')
  const [switched, setSwitched] = useState(true)
  const [alertOpen, setAlertOpen] = useState(true)
  const [progress, setProgress] = useState(64)
  const [commandOpen, setCommandOpen] = useState(false)
  const [filters, setFilters] = useState([
    { id: 'sev', label: 'Severity', value: 'critical' },
    { id: 'env', label: 'Env', value: 'production' },
  ])
  const [activeView, setActiveView] = useState('v1')

  const commands = [
    { id: 'scan', title: 'Run full engine scan', subtitle: 'All engines', group: 'Actions', icon: <Rocket />, run: () => {} },
    { id: 'isolate', title: 'Isolate host prod-web-01', group: 'Actions', icon: <ShieldCheck />, run: () => {} },
    { id: 'crit', title: 'Show critical findings (24h)', group: 'Navigate', icon: <Search />, run: () => {} },
    { id: 'notif', title: 'Open notifications', group: 'Navigate', icon: <Bell />, run: () => {} },
  ]

  return (
    <div className="mx-auto w-full max-w-6xl px-4 py-8 sm:px-6">
      <div className="flex flex-col gap-10">
        <ThemeControls />

        {/* ── Buttons ─────────────────────────────────────────────────── */}
        <Section
          id="buttons"
          title="Button"
          description="Five variants × five sizes, with loading, icons, and full-width."
        >
          <Field label="Variants">
            <Button variant="primary">Primary</Button>
            <Button variant="secondary">Secondary</Button>
            <Button variant="ghost">Ghost</Button>
            <Button variant="danger" leftIcon={<Trash2 />}>Delete</Button>
            <Button variant="premium" leftIcon={<Sparkles />}>Premium</Button>
          </Field>
          <Field label="Sizes">
            <Button size="xs">XS</Button>
            <Button size="sm">SM</Button>
            <Button size="md">MD</Button>
            <Button size="lg">LG</Button>
            <Button size="xl">XL</Button>
          </Field>
          <Field label="States">
            <Button loading>Loading</Button>
            <Button disabled>Disabled</Button>
          </Field>
        </Section>

        {/* ── Form controls ───────────────────────────────────────────── */}
        <Section
          id="forms"
          title="Form controls"
          description="Input, Select, Checkbox, Radio, and Switch — all label/hint/error aware and keyboard accessible."
        >
          <div className="w-56">
            <Input label="Email" placeholder="you@corp.com" hint="Work address" leftAddon={<Search />} />
          </div>
          <div className="w-56">
            <Input label="API key" error="Required field" defaultValue="" />
          </div>
          <div className="w-56">
            <Select
              label="Scan profile"
              options={[
                { value: 'fast', label: 'Fast' },
                { value: 'balanced', label: 'Balanced' },
                { value: 'deep', label: 'Deep' },
              ]}
            />
          </div>
          <Field label="Checkbox">
            <Checkbox
              label="Enable auto-remediation"
              checked={checked}
              onChange={(e) => setChecked(e.target.checked)}
            />
            <Checkbox label="Indeterminate" indeterminate />
            <Checkbox label="Disabled" disabled />
          </Field>
          <Field label="Radio group">
            <RadioGroup
              label="Aggressiveness"
              name="aggr"
              value={radio}
              onChange={setRadio}
              options={[
                { value: 'passive', label: 'Passive' },
                { value: 'balanced', label: 'Balanced' },
                { value: 'aggressive', label: 'Aggressive' },
              ]}
            />
          </Field>
          <Field label="Switch">
            <Switch
              label="Live mode"
              checked={switched}
              onChange={(e) => setSwitched(e.target.checked)}
            />
            <Switch label="Disabled" disabled />
          </Field>
        </Section>

        {/* ── Navigation ──────────────────────────────────────────────── */}
        <Section
          id="tabs"
          title="Tabs & Accordion"
          description="ARIA tablist with arrow-key roving focus, and a single-expand accordion."
        >
          <div className="w-full max-w-md">
            <Tabs defaultValue="overview">
              <TabList>
                <Tab value="overview">Overview</Tab>
                <Tab value="findings">Findings</Tab>
                <Tab value="timeline">Timeline</Tab>
              </TabList>
              <TabPanel value="overview">
                <p className="pt-3 text-sm text-text-secondary">Posture score and KPIs.</p>
              </TabPanel>
              <TabPanel value="findings">
                <p className="pt-3 text-sm text-text-secondary">142 open findings.</p>
              </TabPanel>
              <TabPanel value="timeline">
                <p className="pt-3 text-sm text-text-secondary">Recent activity replay.</p>
              </TabPanel>
            </Tabs>
          </div>
          <div className="w-full max-w-md">
            <Accordion type="single" defaultValue="a1" collapsible>
              <AccordionItem value="a1">
                <AccordionTrigger>What is a finding?</AccordionTrigger>
                <AccordionContent>
                  A correlated, evidence-backed security observation with a severity and remediation path.
                </AccordionContent>
              </AccordionItem>
              <AccordionItem value="a2">
                <AccordionTrigger>How is risk scored?</AccordionTrigger>
                <AccordionContent>
                  Blast radius (SLE/ALE) combined with exploitability signals (KEV/EPSS).
                </AccordionContent>
              </AccordionItem>
            </Accordion>
          </div>
        </Section>

        {/* ── Overlays ────────────────────────────────────────────────── */}
        <Section
          id="overlays"
          title="Overlays"
          description="Modal, Drawer, Tooltip, and Popover — portalled, focus-trapped, Esc-dismissable."
        >
          <Field label="Modal">
            <Button onClick={() => setModalOpen(true)} leftIcon={<Command />}>
              Open modal
            </Button>
          </Field>
          <Field label="Drawer">
            <Button variant="secondary" onClick={() => { setDrawerSide('end'); setDrawerOpen(true) }}>
              From end
            </Button>
            <Button variant="secondary" onClick={() => { setDrawerSide('start'); setDrawerOpen(true) }}>
              From start
            </Button>
          </Field>
          <Field label="Tooltip">
            <Tooltip content="Runs the full engine suite">
              <Button variant="ghost" leftIcon={<Rocket />}>Launch scan</Button>
            </Tooltip>
          </Field>
          <Field label="Popover">
            <Popover trigger={<Button variant="secondary" leftIcon={<Bell />}>Notifications</Button>}>
              <div className="w-56">
                <p className="text-sm font-medium text-text-primary">3 new alerts</p>
                <p className="mt-1 text-xs text-text-tertiary">Critical finding on prod-web-01.</p>
              </div>
            </Popover>
          </Field>
        </Section>

        {/* ── Feedback ────────────────────────────────────────────────── */}
        <Section
          id="feedback"
          title="Feedback & status"
          description="Alert, Badge, Progress, Spinner, Skeleton, and EmptyState."
        >
          <div className="flex w-full flex-col gap-3">
            {alertOpen && (
              <Alert
                variant="danger"
                title="Critical exposure detected"
                dismissible
                onDismiss={() => setAlertOpen(false)}
              >
                An internet-facing host is running a KEV-listed vulnerable service.
              </Alert>
            )}
            <Alert variant="success" title="Scan complete">All engines finished with no errors.</Alert>
            <Alert variant="info">Next scheduled scan in 6 hours.</Alert>
          </div>
          <Field label="Badges">
            <Badge kind="severity" value="critical" />
            <Badge kind="severity" value="high" />
            <Badge kind="status" value="active" dot />
            <Badge kind="kev" />
          </Field>
          <Field label="Progress">
            <div className="w-56">
              <Progress value={progress} showLabel variant="accent" />
            </div>
            <div className="w-56">
              <Progress indeterminate variant="success" />
            </div>
            <Button size="xs" variant="ghost" onClick={() => setProgress((p) => (p + 10) % 110)}>
              +10%
            </Button>
          </Field>
          <Field label="Spinner">
            <Spinner size="sm" />
            <Spinner size="md" />
            <Spinner size="lg" />
          </Field>
          <Field label="Skeleton">
            <div className="w-56 space-y-2">
              <Skeleton className="h-4 w-full" />
              <Skeleton className="h-4 w-2/3" />
            </div>
          </Field>
          <div className="w-full max-w-sm">
            <EmptyState icon="shield" title="No findings" body="This asset is clean." />
          </div>
        </Section>

        {/* ── Identity ────────────────────────────────────────────────── */}
        <Section
          id="identity"
          title="Avatar"
          description="Image with initials fallback, status dots, sizes, and overlapping groups."
        >
          <Field label="Sizes">
            <Avatar name="Ada Lovelace" size="xs" />
            <Avatar name="Grace Hopper" size="sm" />
            <Avatar name="Alan Turing" size="md" status="online" />
            <Avatar name="Katherine Johnson" size="lg" status="busy" />
            <Avatar name="Weissman SOC" size="xl" status="away" />
          </Field>
          <Field label="Group">
            <AvatarGroup max={3}>
              <Avatar name="Ada Lovelace" />
              <Avatar name="Grace Hopper" />
              <Avatar name="Alan Turing" />
              <Avatar name="Katherine Johnson" />
              <Avatar name="Linus Torvalds" />
            </AvatarGroup>
          </Field>
        </Section>

        {/* ── Command Center ──────────────────────────────────────────── */}
        <Section
          id="command-center"
          title="Command Center"
          description="KPI strip with drill-down, sparklines, the ⌘K command bar, and smart filters."
        >
          <div className="w-full">
            <KpiStrip
              items={[
                { label: 'Open findings', value: 142, delta: 8, deltaLabel: 'vs 24h', invertDelta: true, trend: [120, 128, 124, 135, 138, 142] },
                { label: 'Critical', value: 7, delta: -2, deltaLabel: 'vs 24h', invertDelta: true, trend: [11, 10, 9, 9, 8, 7], icon: <ShieldCheck /> },
                { label: 'Resolved (7d)', value: 318, delta: 24, trend: [40, 55, 48, 62, 58, 71] },
                { label: 'Mean time to remediate', value: '4.2', unit: 'h', delta: -0.6, invertDelta: true, trend: [6, 5.5, 5.1, 4.8, 4.4, 4.2] },
              ]}
            />
          </div>
          <Field label="Sparklines">
            <Sparkline data={[3, 7, 4, 9, 6, 11, 8]} label="up trend" />
            <Sparkline data={[11, 8, 9, 5, 6, 3, 2]} variant="danger" label="down trend" />
            <Sparkline data={[5, 5, 6, 5, 6, 5, 5]} variant="success" type="line" showDot label="flat" />
          </Field>
          <Field label="Command Bar (⌘K)">
            <Button leftIcon={<Command />} onClick={() => setCommandOpen(true)}>
              Open command bar
            </Button>
          </Field>
          <div className="w-full">
            <SmartFilterBar
              filters={filters}
              onRemove={(id) => setFilters((f) => f.filter((x) => x.id !== id))}
              onClear={() => setFilters([])}
              savedViews={[
                { id: 'v1', name: 'Critical · Prod' },
                { id: 'v2', name: 'KEV only' },
              ]}
              activeViewId={activeView}
              onApplyView={setActiveView}
              onSaveView={() => {}}
            />
          </div>
        </Section>

        {/* ── Visualizations ──────────────────────────────────────────── */}
        <Section
          id="visualizations"
          title="Visualizations"
          description="Financial blast radius (SLE/ALE) and a compact grid heatmap."
        >
          <div className="w-full max-w-md">
            <BlastRadius
              sle={125000}
              ale={480000}
              crownJewels={[
                { name: 'Customer PII store', value: 210000 },
                { name: 'Payments gateway', value: 160000 },
                { name: 'Source control', value: 90000 },
              ]}
            />
          </div>
          <Field label="MITRE coverage heatmap">
            <MiniHeatmap
              title="Technique coverage"
              variant="danger"
              cellSize={18}
              data={[
                [2, 5, 8, 3, 6, 1],
                [7, 4, 9, 2, 5, 8],
                [1, 6, 3, 7, 4, 2],
                [8, 2, 5, 9, 3, 6],
              ]}
            />
          </Field>
        </Section>

        {/* ── WarRoom & SOAR ──────────────────────────────────────────── */}
        <Section
          id="warroom"
          title="WarRoom & SOAR"
          description="Attack-path kill chain, incident timeline, evidence lightbox, and a playbook stepper."
        >
          <div className="w-full">
            <KillChainPath
              title="Kill chain"
              stages={[
                { id: 'recon', label: 'Recon', status: 'done' },
                { id: 'access', label: 'Initial access', status: 'done' },
                { id: 'exec', label: 'Execution', status: 'active' },
                { id: 'exfil', label: 'Exfiltration', status: 'blocked', detail: 'DLP blocked' },
                { id: 'impact', label: 'Impact', status: 'pending' },
              ]}
            />
          </div>
          <div className="w-full max-w-md">
            <Timeline
              items={[
                { id: 1, title: 'Finding detected', description: 'KEV service on prod-web-01', timestamp: '09:12', variant: 'danger' },
                { id: 2, title: 'Auto-triaged', description: 'Correlated to CVE-2024-3400', timestamp: '09:13', variant: 'warning' },
                { id: 3, title: 'Playbook launched', description: 'Ransomware containment', timestamp: '09:15', variant: 'info' },
                { id: 4, title: 'Host isolated', timestamp: '09:16', variant: 'success' },
              ]}
            />
          </div>
          <div className="w-full max-w-md">
            <Stepper
              steps={[
                { id: 't', label: 'Trigger', status: 'complete' },
                { id: 'e', label: 'Enrich', status: 'complete' },
                { id: 'c', label: 'Contain', status: 'current' },
                { id: 'n', label: 'Notify', status: 'upcoming' },
              ]}
            />
          </div>
          <Field label="Evidence gallery">
            <div className="w-72">
              <EvidenceGallery
                items={[
                  { id: 'a', kind: 'log', caption: 'Access log', content: 'GET /admin 200\nPOST /login 401 x12' },
                  { id: 'b', kind: 'file', caption: 'memory-dump.raw' },
                  { id: 'c', kind: 'log', caption: 'EDR alert', content: 'proc: powershell -enc …' },
                ]}
              />
            </div>
          </Field>
          <Field label="Playbook nodes">
            <PlaybookNode type="trigger" title="On critical finding" summary="severity = critical" />
            <PlaybookNode type="condition" title="Is KEV-listed?" status="success" />
            <PlaybookNode type="action" title="Isolate host" summary="EDR · prod-web-01" selected />
            <PlaybookNode type="notify" title="Page on-call" summary="Slack + PagerDuty" />
          </Field>
        </Section>

        {/* ── Enterprise & Marketplace ────────────────────────────────── */}
        <Section
          id="enterprise"
          title="Enterprise & Marketplace"
          description="Live white-label studio (drives the brand engine), compliance coverage matrix, and marketplace cards."
        >
          <div className="w-full">
            <WhiteLabelStudio brand={brand} onChange={setBrand} onReset={clearBrand} />
          </div>
          <div className="grid w-full gap-4 sm:grid-cols-2">
            <div className="flex flex-col gap-3">
              <UsageMeter label="Engine scans" used={820} limit={1000} unit="scans" />
              <UsageMeter label="Seats" used={48} limit={50} unit="seats" />
              <UsageMeter label="API calls" used={112000} limit={100000} unit="calls" />
            </div>
            <RiskExplanation
              narrative="This host exposes a KEV-listed RCE directly to the internet; exploitation would give an attacker a foothold adjacent to the payments database."
              likelihood="high"
              impact="high"
              factors={[
                { label: 'Internet-facing asset', level: 'high' },
                { label: 'KEV-listed (actively exploited)', level: 'high' },
                { label: 'Adjacent to crown-jewel data', level: 'medium' },
              ]}
              recommendation="Apply the vendor hotfix within 24h and rotate gateway credentials."
            />
          </div>
          <div className="w-full">
            <ComplianceMatrix
              frameworks={[
                { id: 'iso', label: 'ISO 27001' },
                { id: 'soc2', label: 'SOC 2' },
                { id: 'nist', label: 'NIST CSF' },
                { id: 'cis', label: 'CIS v8' },
              ]}
              controls={[
                { id: 'ac', label: 'Access control', status: { iso: 'covered', soc2: 'covered', nist: 'partial', cis: 'covered' } },
                { id: 'enc', label: 'Encryption at rest', status: { iso: 'covered', soc2: 'partial', nist: 'covered', cis: 'gap' } },
                { id: 'log', label: 'Audit logging', status: { iso: 'partial', soc2: 'covered', nist: 'covered', cis: 'covered' } },
                { id: 'ir', label: 'Incident response', status: { iso: 'gap', soc2: 'partial', nist: 'covered', cis: 'na' } },
              ]}
            />
          </div>
          <div className="grid w-full gap-3 sm:grid-cols-2 lg:grid-cols-3">
            <MarketplaceCard
              name="Dark Web Monitor"
              description="Continuous infostealer + credential-leak surveillance across markets."
              category="Threat Intel"
              version="2.4.0"
              rating={5}
              installs={12800}
              price="$49/mo"
              icon={<Search />}
            />
            <MarketplaceCard
              name="OT/ICS Sentinel"
              description="Passive OT protocol analysis and anomaly detection for plant networks."
              category="OT Security"
              version="1.1.2"
              rating={4}
              installs={3400}
              price="$129/mo"
              icon={<ShieldCheck />}
            />
            <MarketplaceCard
              name="Cloud Posture"
              description="CSPM across AWS/Azure/GCP with drift and blast-radius scoring."
              category="Cloud"
              version="3.0.1"
              rating={4}
              installs={22100}
              price="Free"
              installed
              icon={<Rocket />}
            />
          </div>
        </Section>
      </div>

      <Modal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        title="Isolate host prod-web-01?"
        description="This will sever all network connectivity for the selected asset."
        footer={
          <>
            <Button variant="secondary" onClick={() => setModalOpen(false)}>Cancel</Button>
            <Button variant="danger" leftIcon={<ShieldCheck />} onClick={() => setModalOpen(false)}>
              Isolate now
            </Button>
          </>
        }
      >
        <ModalBody>
          <p className="text-sm text-text-secondary">
            Isolation is reversible from the WarRoom. An audit-trail entry will be recorded.
          </p>
        </ModalBody>
      </Modal>

      <Drawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        side={drawerSide}
        title="Finding detail"
        description="CVE-2024-3400 · GlobalProtect"
      >
        <div className="space-y-3 text-sm text-text-secondary">
          <p>Command injection in the GlobalProtect gateway. Actively exploited (KEV).</p>
          <p>Recommended: apply the vendor hotfix and rotate credentials.</p>
        </div>
      </Drawer>

      <CommandBar open={commandOpen} onOpenChange={setCommandOpen} commands={commands} hotkey={false} />
    </div>
  )
}
