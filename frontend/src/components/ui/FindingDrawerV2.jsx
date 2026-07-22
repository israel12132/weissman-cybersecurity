import Drawer from './Drawer.jsx'
import Tabs, { TabList, Tab, TabPanel } from './Tabs.jsx'
import Badge from './Badge.jsx'
import Timeline from './Timeline.jsx'
import KillChainPath from './KillChainPath.jsx'
import EvidenceGallery from './EvidenceGallery.jsx'
import RiskExplanation from './RiskExplanation.jsx'
import CommentThread from './CommentThread.jsx'
import PresenceStack from './PresenceStack.jsx'

/**
 * FindingDrawerV2 — the composed finding detail experience, assembled entirely
 * from design-system primitives: a Drawer shell with a severity/KEV header,
 * live viewer presence, and tabbed Overview (AI risk + attack path), Timeline,
 * Evidence gallery, and a collaborative Discussion.
 *
 * @param {boolean} open @param {()=>void} onClose
 * @param {{title,severity?,cve?,host?,kev?,subtitle?}} finding
 * @param {object} [risk] — props for RiskExplanation
 * @param {Array} [attackPath] — stages for KillChainPath
 * @param {Array} [timeline] — items for Timeline
 * @param {Array} [evidence] — items for EvidenceGallery
 * @param {Array} [comments] @param {(text:string)=>void} [onComment]
 * @param {Array} [viewers] — users for PresenceStack
 */
export default function FindingDrawerV2({
  open,
  onClose,
  finding = {},
  risk,
  attackPath = [],
  timeline = [],
  evidence = [],
  comments = [],
  onComment,
  viewers = [],
}) {
  return (
    <Drawer
      open={open}
      onClose={onClose}
      side="end"
      size="lg"
      title={finding.title || 'Finding'}
      description={finding.subtitle || finding.cve || undefined}
    >
      <div className="flex flex-col gap-4">
        {/* Header meta */}
        <div className="flex flex-wrap items-center gap-2">
          {finding.severity && <Badge kind="severity" value={finding.severity} />}
          {finding.kev && <Badge kind="kev" />}
          {finding.host && (
            <span className="rounded-md bg-bg-3 px-2 py-0.5 font-mono text-xs text-text-tertiary">
              {finding.host}
            </span>
          )}
          {viewers.length > 0 && <PresenceStack users={viewers} size="xs" className="ms-auto" />}
        </div>

        <Tabs defaultValue="overview">
          <TabList>
            <Tab value="overview">Overview</Tab>
            <Tab value="timeline">Timeline</Tab>
            <Tab value="evidence">Evidence</Tab>
            <Tab value="discussion">Discussion</Tab>
          </TabList>

          <TabPanel value="overview">
            <div className="flex flex-col gap-4 pt-3">
              {risk && <RiskExplanation {...risk} />}
              {attackPath.length > 0 && (
                <div>
                  <p className="mb-2 text-[10px] uppercase tracking-widest text-text-muted">Attack path</p>
                  <KillChainPath stages={attackPath} />
                </div>
              )}
            </div>
          </TabPanel>

          <TabPanel value="timeline">
            <div className="pt-3">
              <Timeline items={timeline} />
            </div>
          </TabPanel>

          <TabPanel value="evidence">
            <div className="pt-3">
              <EvidenceGallery items={evidence} />
            </div>
          </TabPanel>

          <TabPanel value="discussion">
            <div className="pt-3">
              <CommentThread comments={comments} onSubmit={onComment} />
            </div>
          </TabPanel>
        </Tabs>
      </div>
    </Drawer>
  )
}

export { FindingDrawerV2 }
