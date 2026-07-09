import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useSyncHubScanParams } from '../hooks/useLaunchEngineScan'
import { useState, useEffect, useCallback, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { motion, AnimatePresence } from 'framer-motion'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useWeissmanEnginePage, applyHistoryFindings } from '../hooks/useWeissmanEnginePage'
import { apiFetch } from '../lib/apiBase'
import { useJobPoll, resolveJobFindings, uiJobStatus } from '../lib/useJobPoll'
import DataTable from '../components/ui/DataTable'
import { createColumnHelper } from '@tanstack/react-table'

const columnHelper = createColumnHelper()

// Agentless CSPM/CNAPP — `cloud_posture` engine (Wiz-style cross-account read-only IAM role).
// Every control maps 1:1 to CloudScanOptions / ArsenalConfig keys in the scan body.
const ENGINE = 'cloud_posture'
const ACCENT = '#f97316'

const SERVICE_TOGGLES = [
  { key: 'svc_iam', labelKey: 'pages.cloudPostureCommandCenter.svc_iam_label', hintKey: 'pages.cloudPostureCommandCenter.svc_iam_hint', service: 'iam' },
  { key: 'svc_s3', labelKey: 'pages.cloudPostureCommandCenter.svc_s3_label', hintKey: 'pages.cloudPostureCommandCenter.svc_s3_hint', service: 's3' },
  { key: 'svc_account', labelKey: 'pages.cloudPostureCommandCenter.svc_account_label', hintKey: 'pages.cloudPostureCommandCenter.svc_account_hint', service: 'account' },
  { key: 'svc_ec2', labelKey: 'pages.cloudPostureCommandCenter.svc_ec2_label', hintKey: 'pages.cloudPostureCommandCenter.svc_ec2_hint', service: 'ec2' },
  { key: 'svc_elb', labelKey: 'pages.cloudPostureCommandCenter.svc_elb_label', hintKey: 'pages.cloudPostureCommandCenter.svc_elb_hint', service: 'elb' },
  { key: 'svc_eks', labelKey: 'pages.cloudPostureCommandCenter.svc_eks_label', hintKey: 'pages.cloudPostureCommandCenter.svc_eks_hint', service: 'eks' },
  { key: 'svc_ecs', labelKey: 'pages.cloudPostureCommandCenter.svc_ecs_label', hintKey: 'pages.cloudPostureCommandCenter.svc_ecs_hint', service: 'ecs' },
  { key: 'svc_lambda', labelKey: 'pages.cloudPostureCommandCenter.svc_lambda_label', hintKey: 'pages.cloudPostureCommandCenter.svc_lambda_hint', service: 'lambda' },
  { key: 'svc_rds', labelKey: 'pages.cloudPostureCommandCenter.svc_rds_label', hintKey: 'pages.cloudPostureCommandCenter.svc_rds_hint', service: 'rds' },
  { key: 'svc_elasticache', labelKey: 'pages.cloudPostureCommandCenter.svc_elasticache_label', hintKey: 'pages.cloudPostureCommandCenter.svc_elasticache_hint', service: 'elasticache' },
  { key: 'svc_kms', labelKey: 'pages.cloudPostureCommandCenter.svc_kms_label', hintKey: 'pages.cloudPostureCommandCenter.svc_kms_hint', service: 'kms' },
  { key: 'svc_secrets', labelKey: 'pages.cloudPostureCommandCenter.svc_secrets_label', hintKey: 'pages.cloudPostureCommandCenter.svc_secrets_hint', service: 'secrets' },
  { key: 'svc_messaging', labelKey: 'pages.cloudPostureCommandCenter.svc_messaging_label', hintKey: 'pages.cloudPostureCommandCenter.svc_messaging_hint', service: 'messaging' },
  { key: 'svc_ssm', labelKey: 'pages.cloudPostureCommandCenter.svc_ssm_label', hintKey: 'pages.cloudPostureCommandCenter.svc_ssm_hint', service: 'ssm' },
  { key: 'svc_cloudtrail', labelKey: 'pages.cloudPostureCommandCenter.svc_cloudtrail_label', hintKey: 'pages.cloudPostureCommandCenter.svc_cloudtrail_hint', service: 'cloudtrail' },
  { key: 'svc_config', labelKey: 'pages.cloudPostureCommandCenter.svc_config_label', hintKey: 'pages.cloudPostureCommandCenter.svc_config_hint', service: 'config' },
  { key: 'svc_guardduty', labelKey: 'pages.cloudPostureCommandCenter.svc_guardduty_label', hintKey: 'pages.cloudPostureCommandCenter.svc_guardduty_hint', service: 'guardduty' },
  { key: 'svc_accessanalyzer', labelKey: 'pages.cloudPostureCommandCenter.svc_accessanalyzer_label', hintKey: 'pages.cloudPostureCommandCenter.svc_accessanalyzer_hint', service: 'accessanalyzer' },
  { key: 'svc_ecr', labelKey: 'pages.cloudPostureCommandCenter.svc_ecr_label', hintKey: 'pages.cloudPostureCommandCenter.svc_ecr_hint', service: 'ecr' },
  { key: 'svc_acm', labelKey: 'pages.cloudPostureCommandCenter.svc_acm_label', hintKey: 'pages.cloudPostureCommandCenter.svc_acm_hint', service: 'acm' },
  { key: 'svc_dynamodb', labelKey: 'pages.cloudPostureCommandCenter.svc_dynamodb_label', hintKey: 'pages.cloudPostureCommandCenter.svc_dynamodb_hint', service: 'dynamodb' },
  { key: 'svc_apigateway', labelKey: 'pages.cloudPostureCommandCenter.svc_apigateway_label', hintKey: 'pages.cloudPostureCommandCenter.svc_apigateway_hint', service: 'apigateway' },
  { key: 'svc_opensearch', labelKey: 'pages.cloudPostureCommandCenter.svc_opensearch_label', hintKey: 'pages.cloudPostureCommandCenter.svc_opensearch_hint', service: 'opensearch' },
  { key: 'svc_cloudfront', labelKey: 'pages.cloudPostureCommandCenter.svc_cloudfront_label', hintKey: 'pages.cloudPostureCommandCenter.svc_cloudfront_hint', service: 'cloudfront' },
  { key: 'svc_route53', labelKey: 'pages.cloudPostureCommandCenter.svc_route53_label', hintKey: 'pages.cloudPostureCommandCenter.svc_route53_hint', service: 'route53' },
  { key: 'svc_eventbridge', labelKey: 'pages.cloudPostureCommandCenter.svc_eventbridge_label', hintKey: 'pages.cloudPostureCommandCenter.svc_eventbridge_hint', service: 'eventbridge' },
  { key: 'svc_wafv2', labelKey: 'pages.cloudPostureCommandCenter.svc_wafv2_label', hintKey: 'pages.cloudPostureCommandCenter.svc_wafv2_hint', service: 'wafv2' },
  { key: 'svc_logs', labelKey: 'pages.cloudPostureCommandCenter.svc_logs_label', hintKey: 'pages.cloudPostureCommandCenter.svc_logs_hint', service: 'logs' },
  { key: 'svc_redshift', labelKey: 'pages.cloudPostureCommandCenter.svc_redshift_label', hintKey: 'pages.cloudPostureCommandCenter.svc_redshift_hint', service: 'redshift' },
  { key: 'svc_documentdb', labelKey: 'pages.cloudPostureCommandCenter.svc_documentdb_label', hintKey: 'pages.cloudPostureCommandCenter.svc_documentdb_hint', service: 'documentdb' },
  { key: 'svc_neptune', labelKey: 'pages.cloudPostureCommandCenter.svc_neptune_label', hintKey: 'pages.cloudPostureCommandCenter.svc_neptune_hint', service: 'neptune' },
  { key: 'svc_memorydb', labelKey: 'pages.cloudPostureCommandCenter.svc_memorydb_label', hintKey: 'pages.cloudPostureCommandCenter.svc_memorydb_hint', service: 'memorydb' },
  { key: 'svc_backup', labelKey: 'pages.cloudPostureCommandCenter.svc_backup_label', hintKey: 'pages.cloudPostureCommandCenter.svc_backup_hint', service: 'backup' },
  { key: 'svc_organizations', labelKey: 'pages.cloudPostureCommandCenter.svc_organizations_label', hintKey: 'pages.cloudPostureCommandCenter.svc_organizations_hint', service: 'organizations' },
  { key: 'svc_sfn', labelKey: 'pages.cloudPostureCommandCenter.svc_sfn_label', hintKey: 'pages.cloudPostureCommandCenter.svc_sfn_hint', service: 'sfn' },
  { key: 'svc_sso', labelKey: 'pages.cloudPostureCommandCenter.svc_sso_label', hintKey: 'pages.cloudPostureCommandCenter.svc_sso_hint', service: 'sso' },
]

const CHECK_TOGGLES = [
  { key: 'check_root_account', labelKey: 'pages.cloudPostureCommandCenter.check_root_account', defaultVal: true },
  { key: 'check_password_policy', labelKey: 'pages.cloudPostureCommandCenter.check_password_policy', defaultVal: true },
  { key: 'check_imds', labelKey: 'pages.cloudPostureCommandCenter.check_imds', defaultVal: true },
  { key: 'check_flow_logs', labelKey: 'pages.cloudPostureCommandCenter.check_flow_logs', defaultVal: true },
  { key: 'check_ssm_public_params', labelKey: 'pages.cloudPostureCommandCenter.check_ssm_public_params', defaultVal: true },
  { key: 'check_cloudtrail', labelKey: 'pages.cloudPostureCommandCenter.check_cloudtrail', defaultVal: true },
  { key: 'check_config_recorder', labelKey: 'pages.cloudPostureCommandCenter.check_config_recorder', defaultVal: true },
  { key: 'check_guardduty', labelKey: 'pages.cloudPostureCommandCenter.check_guardduty', defaultVal: true },
  { key: 'check_access_analyzer', labelKey: 'pages.cloudPostureCommandCenter.check_access_analyzer', defaultVal: true },
  { key: 'check_account_s3_block', labelKey: 'pages.cloudPostureCommandCenter.check_account_s3_block', defaultVal: true },
  { key: 'check_rds', labelKey: 'pages.cloudPostureCommandCenter.check_rds', defaultVal: true },
  { key: 'check_lambda', labelKey: 'pages.cloudPostureCommandCenter.check_lambda', defaultVal: true },
  { key: 'check_lambda_urls', labelKey: 'pages.cloudPostureCommandCenter.check_lambda_urls', defaultVal: true },
  { key: 'check_eks', labelKey: 'pages.cloudPostureCommandCenter.check_eks', defaultVal: true },
  { key: 'check_elb', labelKey: 'pages.cloudPostureCommandCenter.check_elb', defaultVal: true },
  { key: 'check_ecs', labelKey: 'pages.cloudPostureCommandCenter.check_ecs', defaultVal: true },
  { key: 'check_elasticache', labelKey: 'pages.cloudPostureCommandCenter.check_elasticache', defaultVal: true },
  { key: 'check_secrets_manager', labelKey: 'pages.cloudPostureCommandCenter.check_secrets_manager', defaultVal: true },
  { key: 'check_messaging', labelKey: 'pages.cloudPostureCommandCenter.check_messaging', defaultVal: true },
  { key: 'check_public_snapshots', labelKey: 'pages.cloudPostureCommandCenter.check_public_snapshots', defaultVal: true },
  { key: 'check_s3_policy_public', labelKey: 'pages.cloudPostureCommandCenter.check_s3_policy_public', defaultVal: true },
  { key: 'check_iam_wildcards', labelKey: 'pages.cloudPostureCommandCenter.check_iam_wildcards', defaultVal: true },
  { key: 'check_default_sg', labelKey: 'pages.cloudPostureCommandCenter.check_default_sg', defaultVal: true },
  { key: 'check_ecr', labelKey: 'pages.cloudPostureCommandCenter.check_ecr', defaultVal: true },
  { key: 'check_acm', labelKey: 'pages.cloudPostureCommandCenter.check_acm', defaultVal: true },
  { key: 'check_s3_versioning', labelKey: 'pages.cloudPostureCommandCenter.check_s3_versioning', defaultVal: true },
  { key: 'check_dynamodb', labelKey: 'pages.cloudPostureCommandCenter.check_dynamodb', defaultVal: true },
  { key: 'check_apigateway', labelKey: 'pages.cloudPostureCommandCenter.check_apigateway', defaultVal: true },
  { key: 'check_opensearch', labelKey: 'pages.cloudPostureCommandCenter.check_opensearch', defaultVal: true },
  { key: 'check_cloudfront', labelKey: 'pages.cloudPostureCommandCenter.check_cloudfront', defaultVal: true },
  { key: 'check_route53', labelKey: 'pages.cloudPostureCommandCenter.check_route53', defaultVal: true },
  { key: 'check_eventbridge', labelKey: 'pages.cloudPostureCommandCenter.check_eventbridge', defaultVal: true },
  { key: 'check_wafv2', labelKey: 'pages.cloudPostureCommandCenter.check_wafv2', defaultVal: true },
  { key: 'check_cloudwatch_logs', labelKey: 'pages.cloudPostureCommandCenter.check_cloudwatch_logs', defaultVal: true },
  { key: 'check_redshift', labelKey: 'pages.cloudPostureCommandCenter.check_redshift', defaultVal: true },
  { key: 'check_documentdb', labelKey: 'pages.cloudPostureCommandCenter.check_documentdb', defaultVal: true },
  { key: 'check_s3_object_lock', labelKey: 'pages.cloudPostureCommandCenter.check_s3_object_lock', defaultVal: true },
  { key: 'check_neptune', labelKey: 'pages.cloudPostureCommandCenter.check_neptune', defaultVal: true },
  { key: 'check_memorydb', labelKey: 'pages.cloudPostureCommandCenter.check_memorydb', defaultVal: true },
  { key: 'check_backup', labelKey: 'pages.cloudPostureCommandCenter.check_backup', defaultVal: true },
  { key: 'check_organizations', labelKey: 'pages.cloudPostureCommandCenter.check_organizations', defaultVal: true },
  { key: 'check_sfn', labelKey: 'pages.cloudPostureCommandCenter.check_sfn', defaultVal: true },
  { key: 'check_sso', labelKey: 'pages.cloudPostureCommandCenter.check_sso', defaultVal: true },
  { key: 'check_graph_paths', labelKey: 'pages.cloudPostureCommandCenter.check_graph_paths', defaultVal: true },
  { key: 'include_attack_paths', labelKey: 'pages.cloudPostureCommandCenter.include_attack_paths', defaultVal: true },
  { key: 'include_security_graph', labelKey: 'pages.cloudPostureCommandCenter.include_security_graph', defaultVal: true },
]

const FRAMEWORKS = ['CIS', 'SOC2', 'ISO27001', 'PCI', 'NIST', 'GDPR']

const DOMAINS = [
  { key: 'identity', labelKey: 'pages.cloudPostureCommandCenter.domain_identity' },
  { key: 'data', labelKey: 'pages.cloudPostureCommandCenter.domain_data' },
  { key: 'network', labelKey: 'pages.cloudPostureCommandCenter.domain_network' },
  { key: 'compute', labelKey: 'pages.cloudPostureCommandCenter.domain_compute' },
  { key: 'governance', labelKey: 'pages.cloudPostureCommandCenter.domain_governance' },
]

const DEFAULT_REGIONS = 'us-east-1,us-west-2,eu-west-1,eu-central-1,ap-southeast-1'

const SEV_STYLE = {
  critical: { text: 'text-rose-300', bd: 'border-rose-500/40', bg: 'bg-rose-500/10', dot: '#fb7185' },
  high: { text: 'text-orange-300', bd: 'border-orange-500/40', bg: 'bg-orange-500/10', dot: '#fb923c' },
  medium: { text: 'text-amber-300', bd: 'border-amber-500/40', bg: 'bg-amber-500/10', dot: '#fbbf24' },
  low: { text: 'text-sky-300', bd: 'border-sky-500/40', bg: 'bg-sky-500/10', dot: '#38bdf8' },
  info: { text: 'text-slate-300', bd: 'border-[var(--border-default)]', bg: 'bg-[var(--row-hover-bg)]', dot: '#94a3b8' },
}

function gradeColor(grade) {
  return {
    'A+': '#34d399', A: '#34d399', 'A-': '#34d399',
    B: '#a3e635', C: '#fbbf24', D: '#fb923c', F: '#fb7185',
  }[grade] || '#fb7185'
}

function sevValue(s) {
  return { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[s] ?? 0
}

function isSummary(f) {
  return f && (f.category === 'summary' || typeof f.posture_score === 'number')
}

function isAttackPath(f) {
  return f && (f.attack_path === true || f.category === 'attack_path')
}

function SubScoreBar({ label, value }) {
  const v = Math.max(0, Math.min(100, Number(value) || 0))
  const color = v >= 85 ? '#34d399' : v >= 60 ? '#a3e635' : v >= 40 ? '#fbbf24' : '#fb7185'
  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <span className="text-[10px] font-mono text-[var(--text-tertiary)]">{label}</span>
        <span className="text-[10px] font-mono" style={{ color }}>{v}</span>
      </div>
      <div className="h-1.5 rounded-full bg-white/8 overflow-hidden">
        <div className="h-full rounded-full transition-all duration-500" style={{ width: `${v}%`, backgroundColor: color }} />
      </div>
    </div>
  )
}

function Scorecard({ summary }) {
  const { t } = useTranslation()
  const columns = useMemo(() => [
    columnHelper.accessor('resource_id', {
      header: () => t('pages.cloudPostureCommandCenter.table_resource'),
      cell: (ctx) => (
        <span className="truncate max-w-[220px] block" title={ctx.row.original.resource_id}>{ctx.row.original.resource_id}</span>
      ),
    }),
    columnHelper.accessor('resource_type', {
      header: () => t('pages.cloudPostureCommandCenter.table_type'),
      cell: (ctx) => ctx.row.original.resource_type,
    }),
    columnHelper.accessor('domain', {
      header: () => t('pages.cloudPostureCommandCenter.table_domain'),
      cell: (ctx) => ctx.row.original.domain,
    }),
    columnHelper.accessor('risk_score', {
      header: () => t('pages.cloudPostureCommandCenter.table_risk'),
      cell: (ctx) => (
        <span className={SEV_STYLE[ctx.row.original.peak_severity]?.text || 'text-[var(--text-tertiary)]'}>{ctx.row.original.risk_score}</span>
      ),
    }),
  ], [t])
  if (!summary) return null
  const score = summary.posture_score ?? summary.score ?? 0
  const grade = summary.grade || '—'
  const color = gradeColor(grade)
  const subscores = summary.subscores || {}
  const counts = summary.severity_counts || {}
  const compliance = summary.compliance_scores || {}
  const graph = summary.security_graph || {}
  const exposure = summary.exposure_metrics || {}
  const detective = summary.detective_coverage || {}
  const roadmap = Array.isArray(summary.remediation_roadmap) ? summary.remediation_roadmap : []
  const riskRegister = Array.isArray(summary.cnapp_risk_register) ? summary.cnapp_risk_register : []
  const perimeter = summary.data_perimeter || {}
  const observability = summary.observability_posture || {}
  const warehouse = summary.warehouse_exposure || {}
  const catalog = summary.cnapp_catalog || {}
  const rulesTriggered = summary.rules_triggered ?? 0

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-6 mb-6">
      <div className="flex flex-col lg:flex-row gap-6">
        <div className="flex items-center gap-5">
          <div className="relative w-28 h-28 shrink-0">
            <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
              <circle cx="50" cy="50" r="42" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="8" />
              <circle cx="50" cy="50" r="42" fill="none" stroke={color} strokeWidth="8"
                strokeDasharray={`${(score / 100) * 264} 264`} strokeLinecap="round" />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-2xl font-bold" style={{ color }}>{grade}</span>
              <span className="text-[10px] font-mono text-[var(--text-muted)]">{score}/100</span>
            </div>
          </div>
          <div>
            <div className="text-[10px] font-mono uppercase tracking-widest text-orange-400/80 mb-1">{t('pages.cloudPostureCommandCenter.scorecard_eyebrow')}</div>
            <h3 className="text-lg font-bold text-white">{t('pages.cloudPostureCommandCenter.scorecard_title')}</h3>
            {summary.account_id && (
              <p className="text-[11px] font-mono text-[var(--text-muted)] mt-1">{t('pages.cloudPostureCommandCenter.scorecard_account', { accountId: summary.account_id })}</p>
            )}
            {rulesTriggered > 0 && (
              <p className="text-[10px] font-mono text-[var(--text-muted)] mt-1">{t('pages.cloudPostureCommandCenter.scorecard_rules_triggered', { count: rulesTriggered })}</p>
            )}
            {catalog.catalog_status === 'complete' && (
              <p className="text-[10px] font-mono text-emerald-400/70 mt-1">
                {t('pages.cloudPostureCommandCenter.scorecard_catalog_complete', { count: catalog.plane_count ?? 37 })}
              </p>
            )}
            <div className="flex flex-wrap gap-2 mt-2">
              {['critical', 'high', 'medium', 'low'].map((s) => counts[s] > 0 && (
                <span key={s} className={`text-[10px] font-mono px-2 py-0.5 rounded border ${SEV_STYLE[s]?.bd} ${SEV_STYLE[s]?.bg} ${SEV_STYLE[s]?.text}`}>
                  {counts[s]} {t(`pages.cloudPostureCommandCenter.sev_${s}`)}
                </span>
              ))}
            </div>
          </div>
        </div>
        <div className="flex-1 grid grid-cols-1 sm:grid-cols-2 gap-3">
          {DOMAINS.map((d) => (
            <SubScoreBar key={d.key} label={t(d.labelKey)} value={subscores[d.key]} />
          ))}
        </div>
      </div>

      {(Object.keys(compliance).length > 0 || graph.node_count > 0 || exposure.blast_radius_index != null) && (
        <div className="mt-5 pt-5 border-t border-[var(--border-subtle)] grid grid-cols-1 lg:grid-cols-3 gap-4">
          {exposure.blast_radius_index != null && (
            <div className="rounded-lg border border-rose-500/20 bg-rose-950/20 px-3 py-3">
              <div className="text-[10px] font-mono uppercase tracking-wider text-rose-300/70 mb-1">{t('pages.cloudPostureCommandCenter.metric_blast_radius')}</div>
              <div className="text-2xl font-bold text-rose-300">{exposure.blast_radius_index}</div>
              <div className="text-[10px] font-mono text-[var(--text-muted)] mt-1">
                {t('pages.cloudPostureCommandCenter.metric_blast_radius_detail', { internet: exposure.internet_exposed ?? 0, privileged: exposure.privileged_assets ?? 0, total: exposure.total_assets ?? 0 })}
              </div>
            </div>
          )}
          {typeof detective.score === 'number' && (
            <div className="rounded-lg border border-cyan-500/20 bg-cyan-950/20 px-3 py-3">
              <div className="text-[10px] font-mono uppercase tracking-wider text-cyan-300/70 mb-1">{t('pages.cloudPostureCommandCenter.metric_detective_coverage')}</div>
              <div className="text-2xl font-bold text-cyan-300">{detective.score}%</div>
              <div className="text-[10px] font-mono text-[var(--text-muted)] mt-1">
                {t('pages.cloudPostureCommandCenter.detective_sources')}
              </div>
            </div>
          )}
          {Object.keys(compliance).length > 0 && (
            <div className="lg:col-span-2">
              <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2">{t('pages.cloudPostureCommandCenter.section_frameworks')}</div>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                {Object.entries(compliance).map(([fw, data]) => (
                  <div key={fw} className="rounded-lg border border-[var(--border-default)] bg-[var(--table-surface)] px-3 py-2">
                    <div className="text-[10px] font-mono text-[var(--text-muted)]">{fw}</div>
                    <div className="flex items-baseline gap-2">
                      <span className="text-sm font-bold" style={{ color: gradeColor(data.grade) }}>{data.grade}</span>
                      <span className="text-[10px] font-mono text-[var(--text-muted)]">{data.score}/100</span>
                    </div>
                    {data.failed_controls > 0 && (
                      <div className="text-[9px] font-mono text-rose-400/70">{t('pages.cloudPostureCommandCenter.compliance_failed', { count: data.failed_controls })}</div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
          {graph.node_count > 0 && (
            <div>
              <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2">{t('pages.cloudPostureCommandCenter.metric_security_graph')}</div>
              <div className="flex gap-4 text-sm font-mono text-[var(--text-tertiary)]">
                <span>{t('pages.cloudPostureCommandCenter.graph_assets', { count: graph.node_count })}</span>
                <span>{t('pages.cloudPostureCommandCenter.graph_relationships', { count: graph.edge_count })}</span>
                {Array.isArray(graph.nodes) && (
                  <span className="text-rose-300/80">
                    {t('pages.cloudPostureCommandCenter.graph_internet_exposed', { count: graph.nodes.filter((n) => n.exposure === 'internet').length })}
                  </span>
                )}
              </div>
              {Array.isArray(graph.nodes) && graph.nodes.length > 0 && (
                <div className="mt-3 max-h-36 overflow-y-auto space-y-1 pr-1">
                  {graph.nodes
                    .filter((n) => n.exposure === 'internet' || (n.risk_tags && n.risk_tags.length > 0))
                    .slice(0, 12)
                    .map((n) => (
                      <div key={n.id} className="flex items-center gap-2 text-[10px] font-mono text-[var(--text-muted)]">
                        <span className={n.exposure === 'internet' ? 'text-rose-400' : 'text-[var(--text-disabled)]'}>●</span>
                        <span className="truncate flex-1">{n.id}</span>
                        {n.risk_tags?.slice(0, 2).map((tag) => (
                          <span key={tag} className="text-[9px] px-1 rounded bg-[var(--row-hover-bg)] text-[var(--text-muted)]">{tag}</span>
                        ))}
                      </div>
                    ))}
                </div>
              )}
              <p className="text-[10px] text-[var(--text-muted)] mt-2 leading-relaxed">
                {t('pages.cloudPostureCommandCenter.graph_description')}
              </p>
            </div>
          )}
        </div>
      )}

      {roadmap.length > 0 && (
        <div className="mt-4 pt-4 border-t border-[var(--border-subtle)]">
          <div className="text-[10px] font-mono uppercase tracking-wider text-emerald-400/80 mb-2">{t('pages.cloudPostureCommandCenter.roadmap_title')}</div>
          <ol className="space-y-2 list-decimal list-inside">
            {roadmap.slice(0, 8).map((item, i) => (
              <li key={i} className="text-[11px] text-[var(--text-tertiary)] leading-relaxed">
                <span className={`font-mono uppercase text-[10px] mr-2 ${SEV_STYLE[item.severity]?.text || 'text-[var(--text-tertiary)]'}`}>{item.severity}</span>
                <span className="text-[var(--text-primary)]">{item.title}</span>
                {item.remediation && <span className="block text-[var(--text-muted)] mt-0.5 ml-5">{item.remediation}</span>}
              </li>
            ))}
          </ol>
        </div>
      )}

      {(riskRegister.length > 0 || perimeter.perimeter_status || warehouse.public_redshift > 0 || observability.waf_no_rules > 0) && (
        <div className="mt-4 pt-4 border-t border-[var(--border-subtle)] grid grid-cols-1 lg:grid-cols-2 gap-4">
          {perimeter.perimeter_status && (
            <div className={`rounded-lg border px-3 py-3 ${
              perimeter.perimeter_status === 'contained'
                ? 'border-emerald-500/20 bg-emerald-950/20'
                : perimeter.perimeter_status === 'breached'
                  ? 'border-rose-500/30 bg-rose-950/30'
                  : 'border-amber-500/25 bg-amber-950/20'
            }`}>
              <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-tertiary)] mb-1">{t('pages.cloudPostureCommandCenter.metric_data_perimeter')}</div>
              <div className={`text-lg font-bold ${
                perimeter.perimeter_status === 'contained' ? 'text-emerald-300' : perimeter.perimeter_status === 'breached' ? 'text-rose-300' : 'text-amber-300'
              }`}>{perimeter.perimeter_status}</div>
              <div className="text-[10px] font-mono text-[var(--text-muted)] mt-1">
                {t('pages.cloudPostureCommandCenter.perimeter_detail', { external: perimeter.access_analyzer_external ?? 0, findings: perimeter.high_severity_data_findings ?? 0 })}
              </div>
            </div>
          )}
          {(observability.waf_no_rules > 0 || observability.logs_no_retention > 0 || observability.waf_no_logging > 0) && (
            <div className="rounded-lg border border-indigo-500/20 bg-indigo-950/20 px-3 py-3">
              <div className="text-[10px] font-mono uppercase tracking-wider text-indigo-300/70 mb-1">{t('pages.cloudPostureCommandCenter.metric_observability')}</div>
              <div className="text-[10px] font-mono text-[var(--text-tertiary)] space-y-0.5">
                {(observability.waf_no_rules ?? 0) > 0 && <div>{t('pages.cloudPostureCommandCenter.obs_waf_no_rules', { count: observability.waf_no_rules })}</div>}
                {(observability.waf_no_logging ?? 0) > 0 && <div>{t('pages.cloudPostureCommandCenter.obs_waf_no_logging', { count: observability.waf_no_logging })}</div>}
                {(observability.logs_no_retention ?? 0) > 0 && <div>{t('pages.cloudPostureCommandCenter.obs_logs_no_retention', { count: observability.logs_no_retention })}</div>}
                {(observability.logs_public_policy ?? 0) > 0 && <div>{t('pages.cloudPostureCommandCenter.obs_logs_public_policy', { count: observability.logs_public_policy })}</div>}
              </div>
            </div>
          )}
          {(warehouse.public_redshift > 0 || warehouse.public_documentdb > 0 || warehouse.public_rds > 0 || warehouse.public_neptune > 0 || warehouse.memorydb_open_acl > 0) && (
            <div className="rounded-lg border border-orange-500/20 bg-orange-950/20 px-3 py-3">
              <div className="text-[10px] font-mono uppercase tracking-wider text-orange-300/70 mb-1">{t('pages.cloudPostureCommandCenter.metric_warehouse')}</div>
              <div className="text-[10px] font-mono text-[var(--text-tertiary)] space-y-0.5">
                {(warehouse.public_redshift ?? 0) > 0 && <div>{t('pages.cloudPostureCommandCenter.wh_public_redshift', { count: warehouse.public_redshift })}</div>}
                {(warehouse.public_documentdb ?? 0) > 0 && <div>{t('pages.cloudPostureCommandCenter.wh_public_documentdb', { count: warehouse.public_documentdb })}</div>}
                {(warehouse.public_rds ?? 0) > 0 && <div>{t('pages.cloudPostureCommandCenter.wh_public_rds', { count: warehouse.public_rds })}</div>}
                {(warehouse.public_neptune ?? 0) > 0 && <div>{t('pages.cloudPostureCommandCenter.wh_public_neptune', { count: warehouse.public_neptune })}</div>}
                {(warehouse.memorydb_open_acl ?? 0) > 0 && <div>{t('pages.cloudPostureCommandCenter.wh_memorydb_open_acl', { count: warehouse.memorydb_open_acl })}</div>}
                {(warehouse.unencrypted_warehouses ?? 0) > 0 && <div>{t('pages.cloudPostureCommandCenter.wh_unencrypted', { count: warehouse.unencrypted_warehouses })}</div>}
              </div>
            </div>
          )}
          {riskRegister.length > 0 && (
            <div className="lg:col-span-2">
              <div className="text-[10px] font-mono uppercase tracking-wider text-violet-300/70 mb-2">{t('pages.cloudPostureCommandCenter.risk_register_title')}</div>
              <DataTable
                columns={columns}
                data={riskRegister}
                animateRows={false}
                getRowId={(item) => item.resource_id}
                searchable
                exportable
                exportFilename="weissman-cloud-risk"
              />
            </div>
          )}
        </div>
      )}
    </motion.div>
  )
}

function FindingCard({ f }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const sev = (f.severity || 'info').toLowerCase()
  const st = SEV_STYLE[sev] || SEV_STYLE.info
  const isPath = isAttackPath(f)
  const compliance = f.compliance || {}
  const steps = Array.isArray(f.steps) ? f.steps : []

  return (
    <div className={`rounded-xl border ${isPath ? 'border-fuchsia-500/40 bg-fuchsia-500/5' : `${st.bd} ${st.bg}`} p-3`}>
      <button type="button" onClick={() => setOpen((o) => !o)} className="w-full text-left flex items-start gap-3">
        <span className="mt-1 w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: isPath ? '#e879f9' : st.dot }} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            {isPath && <span className="text-[10px] font-mono uppercase text-fuchsia-300">☣ {t('pages.cloudPostureCommandCenter.finding_toxic_path')}</span>}
            <span className={`text-[10px] font-mono uppercase tracking-wider ${st.text}`}>{sev}</span>
            {f.domain && <span className="text-[10px] font-mono text-[var(--text-disabled)]">· {f.domain}</span>}
            {f.rule_id && <span className="text-[10px] font-mono text-[var(--text-disabled)]">· {f.rule_id}</span>}
            {f.mitre_attack && <span className="text-[10px] font-mono text-[var(--text-disabled)]">· {f.mitre_attack}</span>}
          </div>
          <div className="text-sm text-[var(--text-primary)] font-medium mt-0.5">{f.title || f.type}</div>
          {f.resource_id && (
            <div className="text-[10px] font-mono text-[var(--text-muted)] mt-0.5 truncate">{f.resource_type}: {f.resource_id}{f.region ? ` · ${f.region}` : ''}</div>
          )}
        </div>
        <span className="text-[var(--text-disabled)] text-xs mt-1">{open ? '▾' : '▸'}</span>
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
            <p className="text-xs text-[var(--text-tertiary)] leading-relaxed mt-2">{f.description}</p>
            {f.toxic_combination && (
              <div className="mt-2 text-[10px] font-mono text-fuchsia-300/80">{t('pages.cloudPostureCommandCenter.finding_combo', { combo: f.toxic_combination })}</div>
            )}
            {steps.length > 0 && (
              <ol className="mt-2 space-y-1 list-decimal list-inside text-[11px] text-[var(--text-tertiary)] font-mono">
                {steps.map((s, i) => <li key={i}>{s}</li>)}
              </ol>
            )}
            {f.remediation && (
              <div className="mt-2 rounded-lg bg-emerald-500/5 border border-emerald-500/20 p-2.5">
                <div className="text-[10px] font-mono uppercase text-emerald-400/70 mb-1">{t('pages.cloudPostureCommandCenter.finding_remediation')}</div>
                <p className="text-[11px] text-emerald-100/80 leading-relaxed">{f.remediation}</p>
              </div>
            )}
            {Object.keys(compliance).length > 0 && (
              <div className="flex flex-wrap gap-1.5 mt-2">
                {Object.entries(compliance).filter(([, v]) => v).map(([k, v]) => (
                  <span key={k} className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-[var(--row-hover-bg)] text-[var(--text-tertiary)] border border-[var(--border-default)]">{k}: {v}</span>
                ))}
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

export default function CloudPostureCommandCenter() {
  const { t } = useTranslation()
  const [clients, setClients] = useState([])
  const [clientId, setClientId] = useState('')
  const { postScan } = useCommandCenterScan(clientId)
  const [roleArn, setRoleArn] = useState('')
  const [externalId, setExternalId] = useState('')
  const [sessionName, setSessionName] = useState('weissman-cspm')
  const [regions, setRegions] = useState(DEFAULT_REGIONS)
  const [frameworks, setFrameworks] = useState(['CIS', 'SOC2', 'ISO27001', 'PCI', 'NIST', 'GDPR'])
  const [minSeverity, setMinSeverity] = useState('info')
  const [intensity, setIntensity] = useState('normal')
  const [maxResources, setMaxResources] = useState(300)
  const [accessKeyMaxAge, setAccessKeyMaxAge] = useState(90)
  const [acmExpiryDays, setAcmExpiryDays] = useState(30)
  const [services, setServices] = useState(() =>
    Object.fromEntries(SERVICE_TOGGLES.map((s) => [s.key, true])),
  )
  const [toggles, setToggles] = useState(() =>
    Object.fromEntries(CHECK_TOGGLES.map((tg) => [tg.key, tg.defaultVal])),
  )
  const [showParams, setShowParams] = useState(true)
  const [status, setStatus] = useState('idle')
  const [lastRun, setLastRun] = useState(null)
  const [findings, setFindings] = useState([])
  const [pendingJobId, setPendingJobId] = useState(null)
  const [toast, setToast] = useState(null)

  const detailFindings = useMemo(
    () => findings.filter((f) => !isSummary(f) && !isAttackPath(f)),
    [findings],
  )

  const {
    filteredFindings,
    counts,
    searchQuery,
    setSearchQuery,
    severityFilter,
    setSeverityFilter,
    exportCsv,
    refreshFromHistory,
    historyLoading,
    lastUpdated,
    lastJobId,
    setLastUpdated,
    setLastJobId,
  } = useWeissmanEnginePage(ENGINE, detailFindings)

  useEffect(() => {
    refreshFromHistory().then((run) => {
      if (run?.findings?.length) {
        applyHistoryFindings(run, setFindings, { setLastUpdated, setJobId: setLastJobId })
      }
    })
  }, [refreshFromHistory, setLastUpdated, setLastJobId])

  const handleRefresh = useCallback(async () => {
    const run = await refreshFromHistory()
    applyHistoryFindings(run, setFindings, { setLastUpdated, setJobId: setLastJobId })
  }, [refreshFromHistory, setLastUpdated, setLastJobId])

  useEffect(() => {
    apiFetch('/api/clients').then((r) => (r.ok ? r.json() : [])).then((d) => { if (Array.isArray(d)) setClients(d) }).catch(() => {})
  }, [])

  useEffect(() => {
    if (!clientId) return
    const c = clients.find((x) => String(x.id) === String(clientId))
    if (!c) return
    if (c.aws_cross_account_role_arn) setRoleArn(c.aws_cross_account_role_arn)
    if (c.aws_external_id) setExternalId(c.aws_external_id)
  }, [clientId, clients])

  const showToast = useCallback((sev, msg) => {
    const id = Date.now()
    setToast({ id, sev, msg })
    setTimeout(() => setToast((x) => (x?.id === id ? null : x)), 5000)
  }, [])

  useJobPoll(pendingJobId, {
    enabled: Boolean(pendingJobId),
    onComplete: async (job) => {
      setStatus(uiJobStatus(job.status))
      setLastRun(new Date().toLocaleTimeString())
      const fs = await resolveJobFindings(job, ENGINE, clientId)
      setFindings(Array.isArray(fs) ? fs : [])
      setLastUpdated(new Date().toISOString())
      if (pendingJobId) setLastJobId(pendingJobId)
      setPendingJobId(null)
    },
  })

  const enabledServices = useMemo(
    () => SERVICE_TOGGLES.filter((s) => services[s.key]).map((s) => s.service),
    [services],
  )

  const buildBody = useCallback(() => {
    const body = {
      engine: ENGINE,
      target: roleArn.trim() || 'aws-account',
      aws_cross_account_role_arn: roleArn.trim(),
      aws_external_id: externalId.trim(),
      aws_role_session_name: sessionName.trim() || 'weissman-cspm',
      regions: regions.trim(),
      services: enabledServices.join(','),
      frameworks: frameworks.join(','),
      min_severity: minSeverity,
      intensity,
      max_resources_per_service: Number(maxResources) || 300,
      access_key_max_age_days: Number(accessKeyMaxAge) || 90,
      acm_expiry_days: Number(acmExpiryDays) || 30,
      ...toggles,
    }
    if (clientId) body.client_id = Number(clientId)
    return body
  }, [roleArn, externalId, sessionName, regions, enabledServices, frameworks, minSeverity, intensity, maxResources, accessKeyMaxAge, acmExpiryDays, toggles, clientId])

  const hubScanParams = useMemo(() => {
    const { engine, target, client_id, ...rest } = buildBody()
    return rest
  }, [buildBody])
  useSyncHubScanParams(ENGINE, hubScanParams)

  const handleRun = useCallback(async () => {
    if (!clientId) { showToast('error', t('pages.cloudPostureCommandCenter.toast_select_client')); return }
    if (!roleArn.trim()) { showToast('error', t('pages.cloudPostureCommandCenter.toast_role_required')); return }
    setStatus('running'); setFindings([])
    try {
      const { ok, data: d, status } = await postScan(buildBody())
      if (!ok) { setStatus('error'); showToast('error', d.detail || t('pages.cloudPostureCommandCenter.toast_scan_failed')); return }
      const jobId = d.job_id ?? ''
      showToast('info', t('pages.cloudPostureCommandCenter.toast_scan_queued', { jobId }))
      if (jobId) setPendingJobId(jobId); else setStatus('error')
    } catch (e) {
      setStatus('error'); showToast('error', e?.message ?? t('pages.cloudPostureCommandCenter.toast_scan_failed'))
    }
  }, [clientId, roleArn, buildBody, showToast, t])

  const summary = useMemo(() => findings.find(isSummary), [findings])
  const attackPaths = useMemo(() => findings.filter(isAttackPath), [findings])

  const statusColor = { idle: '#475569', running: '#f97316', completed: '#4ade80', error: '#ef4444' }[status]

  const toggleFramework = (fw) => {
    setFrameworks((prev) => (prev.includes(fw) ? prev.filter((x) => x !== fw) : [...prev, fw]))
  }

  return (
    <PageShell
      hideHubParams
      title={t('pages.cloudPostureCommandCenter.title')}
      badge={t('pages.cloudPostureCommandCenter.badge')}
      badgeColor="#f97316"
      subtitle={t('pages.cloudPostureCommandCenter.subtitle')}
      actions={(
        <ShellScanActions
          onRefresh={handleRefresh}
          onExport={exportCsv}
          refreshLoading={historyLoading}
          refreshDisabled={status === 'running'}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      {toast && (
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-[var(--bg-1)] border-orange-500/30 text-orange-200'}`}>
          {toast.msg}
        </div>
      )}

      <div className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-5 mb-6">
        <div className="flex flex-wrap items-end gap-4">
          <div className="flex flex-col gap-1">
            <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">{t('pages.cloudPostureCommandCenter.field_client_label')}</label>
            <select value={clientId} onChange={(e) => setClientId(e.target.value)}
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-orange-500/40 min-w-[180px]">
              <option value="">{t('pages.cloudPostureCommandCenter.select_client_placeholder')}</option>
              {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          </div>
          <div className="flex flex-col gap-1 flex-1 min-w-[280px]">
            <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">{t('pages.cloudPostureCommandCenter.field_role_arn_label')}</label>
            <input type="text" value={roleArn} onChange={(e) => setRoleArn(e.target.value)}
              placeholder="arn:aws:iam::123456789012:role/WeissmanReadOnly"
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-orange-500/40" />
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full" style={{ backgroundColor: statusColor, boxShadow: status === 'running' ? '0 0 6px #f97316' : 'none' }} />
            <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase">{t(`pages.cloudPostureCommandCenter.status_${status}`)}</span>
          </div>
          <button type="button" onClick={handleRun} disabled={status === 'running' || !clientId}
            className="px-5 py-2 rounded-xl font-mono text-sm border border-orange-500/40 text-orange-300 bg-orange-500/10 hover:bg-orange-500/20 transition-all disabled:opacity-40 disabled:cursor-not-allowed">
            {status === 'running' ? `⟳ ${t('pages.cloudPostureCommandCenter.btn_scanning')}` : `▶ ${t('pages.cloudPostureCommandCenter.btn_run_scan')}`}
          </button>
          <button type="button" onClick={() => setShowParams((s) => !s)}
            className="px-3 py-2 rounded-xl font-mono text-xs border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-[var(--text-secondary)] hover:border-[var(--border-strong)] transition-all">
            {`${showParams ? '▾' : '▸'} ${t('pages.cloudPostureCommandCenter.parameters')}`}
          </button>
        </div>

        <AnimatePresence initial={false}>
          {showParams && (
            <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
              <div className="mt-5 pt-5 border-t border-[var(--border-subtle)] space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{t('pages.cloudPostureCommandCenter.field_external_id_label')}</label>
                    <input type="text" value={externalId} onChange={(e) => setExternalId(e.target.value)} placeholder={t('pages.cloudPostureCommandCenter.field_external_id_placeholder')}
                      className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-[11px] text-[var(--text-secondary)] font-mono" />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{t('pages.cloudPostureCommandCenter.field_session_name_label')}</label>
                    <input type="text" value={sessionName} onChange={(e) => setSessionName(e.target.value)}
                      className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-[11px] text-[var(--text-secondary)] font-mono" />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{t('pages.cloudPostureCommandCenter.field_regions_label')}</label>
                    <input type="text" value={regions} onChange={(e) => setRegions(e.target.value)}
                      className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-[11px] text-[var(--text-secondary)] font-mono" />
                  </div>
                </div>

                <div>
                  <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2">{t('pages.cloudPostureCommandCenter.section_services')}</div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-1.5">
                    {SERVICE_TOGGLES.map((s) => (
                      <label key={s.key} title={t(s.hintKey)} className="flex items-center gap-2 text-xs font-mono text-[var(--text-secondary)] cursor-pointer">
                        <input type="checkbox" checked={!!services[s.key]} onChange={(e) => setServices((p) => ({ ...p, [s.key]: e.target.checked }))} className="accent-orange-500" />
                        {t(s.labelKey)}
                      </label>
                    ))}
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <div>
                    <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2">{t('pages.cloudPostureCommandCenter.section_deep_checks')}</div>
                    <div className="grid grid-cols-1 gap-1.5">
                      {CHECK_TOGGLES.map((tg) => (
                        <label key={tg.key} className="flex items-center gap-2 text-xs font-mono text-[var(--text-secondary)] cursor-pointer">
                          <input type="checkbox" checked={!!toggles[tg.key]} onChange={(e) => setToggles((p) => ({ ...p, [tg.key]: e.target.checked }))} className="accent-orange-500" />
                          {t(tg.labelKey)}
                        </label>
                      ))}
                    </div>
                  </div>
                  <div className="space-y-4">
                    <div>
                      <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2">{t('pages.cloudPostureCommandCenter.section_frameworks')}</div>
                      <div className="flex flex-wrap gap-2">
                        {FRAMEWORKS.map((fw) => (
                          <button key={fw} type="button" onClick={() => toggleFramework(fw)}
                            className={`px-2.5 py-1 rounded-lg text-[10px] font-mono border transition-all ${frameworks.includes(fw) ? 'border-orange-500/40 bg-orange-500/10 text-orange-300' : 'border-[var(--border-default)] text-[var(--text-muted)]'}`}>
                            {fw}
                          </button>
                        ))}
                      </div>
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{t('pages.cloudPostureCommandCenter.field_min_severity_label')}</label>
                        <select value={minSeverity} onChange={(e) => setMinSeverity(e.target.value)}
                          className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-[11px] text-[var(--text-secondary)] font-mono">
                          {['info', 'low', 'medium', 'high', 'critical'].map((s) => <option key={s} value={s}>{t(`pages.cloudPostureCommandCenter.sev_${s}`)}</option>)}
                        </select>
                      </div>
                      <div>
                        <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{t('pages.cloudPostureCommandCenter.field_intensity_label')}</label>
                        <select value={intensity} onChange={(e) => setIntensity(e.target.value)}
                          className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-[11px] text-[var(--text-secondary)] font-mono">
                          <option value="light">{t('pages.cloudPostureCommandCenter.intensity_light')}</option>
                          <option value="normal">{t('pages.cloudPostureCommandCenter.intensity_normal')}</option>
                          <option value="aggressive">{t('pages.cloudPostureCommandCenter.intensity_aggressive')}</option>
                        </select>
                      </div>
                      <div>
                        <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{t('pages.cloudPostureCommandCenter.field_max_resources_label')}</label>
                        <input type="number" min="10" max="5000" value={maxResources} onChange={(e) => setMaxResources(e.target.value)}
                          className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-[11px] text-[var(--text-secondary)] font-mono" />
                      </div>
                      <div>
                        <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{t('pages.cloudPostureCommandCenter.field_access_key_age_label')}</label>
                        <input type="number" min="1" max="3650" value={accessKeyMaxAge} onChange={(e) => setAccessKeyMaxAge(e.target.value)}
                          className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-[11px] text-[var(--text-secondary)] font-mono" />
                      </div>
                      <div>
                        <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{t('pages.cloudPostureCommandCenter.field_acm_expiry_label')}</label>
                        <input type="number" min="1" max="365" value={acmExpiryDays} onChange={(e) => setAcmExpiryDays(e.target.value)}
                          className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-[11px] text-[var(--text-secondary)] font-mono" />
                      </div>
                    </div>
                  </div>
                </div>

                <div className="rounded-xl border border-cyan-500/20 bg-cyan-950/15 p-4">
                  <div className="text-[10px] font-mono uppercase tracking-wider text-cyan-300/70 mb-2">{t('pages.cloudPostureCommandCenter.connector_title')}</div>
                  <p className="text-[11px] text-[var(--text-tertiary)] leading-relaxed mb-2">
                    {t('pages.cloudPostureCommandCenter.connector_desc')}
                  </p>
                  <pre className="text-[10px] font-mono text-[var(--text-muted)] bg-[var(--bg-3)] rounded-lg p-3 overflow-x-auto whitespace-pre-wrap">{`{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::WEISSMAN_ACCOUNT:root" },
    "Action": "sts:AssumeRole",
    "Condition": { "StringEquals": { "sts:ExternalId": "YOUR_EXTERNAL_ID" } }
  }]
}`}</pre>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {lastRun && <p className="text-[10px] font-mono text-[var(--text-disabled)] mt-3">{t('pages.cloudPostureCommandCenter.last_completed', { time: lastRun })}</p>}
      </div>

      {!clientId && (
        <div className="rounded-xl border border-amber-500/20 bg-amber-950/20 px-4 py-3 text-sm text-amber-200/80 font-mono mb-6">
          {t('pages.cloudPostureCommandCenter.no_client_notice')}
        </div>
      )}

      <Scorecard summary={summary} />

      {attackPaths.length > 0 && (
        <div className="rounded-2xl bg-[var(--table-surface)] border border-fuchsia-500/20 p-4 mb-6">
          <div className="flex items-center gap-2 mb-3">
            <span className="text-lg">☣</span>
            <h3 className="text-sm font-bold text-fuchsia-200">{t('pages.cloudPostureCommandCenter.attack_paths_title')}</h3>
            <span className="text-[10px] font-mono text-[var(--text-disabled)]">({attackPaths.length})</span>
          </div>
          <div className="space-y-2">
            {attackPaths.map((f, i) => <FindingCard key={i} f={f} />)}
          </div>
        </div>
      )}

      <WeissmanFindingsPanel
        findings={detailFindings}
        filteredFindings={filteredFindings}
        counts={counts}
        total={detailFindings.length}
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        severityFilter={severityFilter}
        onSeverityChange={setSeverityFilter}
        pending={status === 'running' && detailFindings.length === 0}
        loading={historyLoading && detailFindings.length === 0}
        lastUpdated={lastUpdated}
        jobId={pendingJobId || lastJobId}
        accent={ACCENT}
        showEmptyReady={status !== 'running' && detailFindings.length === 0}
        emptyReadyTitle={t('pages.cloudPostureCommandCenter.empty_ready')}
        emptyReadyBody={t('pages.cloudPostureCommandCenter.empty_ready')}
        emptyTitle={t('pages.cloudPostureCommandCenter.empty_no_findings')}
        emptyBody={t('pages.cloudPostureCommandCenter.empty_no_findings')}
        renderFinding={(f, i) => <FindingCard key={i} f={f} />}
      />
    </PageShell>
  )
}
