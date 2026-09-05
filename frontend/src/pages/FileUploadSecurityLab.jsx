import { firstClientTarget } from '../lib/clientTarget'
import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useSyncHubScanParams } from '../hooks/useLaunchEngineScan'
import { useState, useEffect, useCallback, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { motion, AnimatePresence } from 'framer-motion'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useWeissmanEnginePage, applyHistoryFindings } from '../hooks/useWeissmanEnginePage'
import { apiFetch } from '../utils/apiFetch'
import { useJobPoll, resolveJobFindings, uiJobStatus } from '../lib/useJobPoll'
import Button from '../components/ui/Button'
import { BoundClientScanField } from '../components/scan/ClientScanBinding'

const ENGINE = 'file_upload'
const ACCENT = '#f97316'

const TOGGLES = [
  { key: 'check_mime_spoof', label: 'MIME / disposition bypass', hint: 'Spoofed Content-Type, empty MIME, octet-stream, RFC5987 filename*', defaultVal: true },
  { key: 'check_double_extension', label: 'Double extensions', hint: 'php.jpg, asp.gif — parser confusion', defaultVal: true },
  { key: 'check_polyglot', label: 'Polyglot files', hint: 'GIF/JPEG/PDF/HTML magic-byte-only validation', defaultVal: true },
  { key: 'check_path_traversal', label: 'Path traversal filenames', hint: '../../ and encoded traversal sequences', defaultVal: true },
  { key: 'check_case_bypass', label: 'Case confusion', hint: '.PhP / mixed-case extensions', defaultVal: true },
  { key: 'check_svg_xss', label: 'SVG stored-XSS surface', hint: 'SVG with script block acceptance', defaultVal: true },
  { key: 'check_config_upload', label: 'Config file upload', hint: '.htaccess / web.config / .env', defaultVal: true },
  { key: 'check_php_bypass', label: 'PHP bypass pack', hint: '.php5 / .phar / .phtml (stack-aware)', defaultVal: true },
  { key: 'check_iis_bypass', label: 'IIS bypass pack', hint: '.aspx;.jpg semicolon + NTFS ADS (Aggressive)', defaultVal: true },
  { key: 'check_dotnet_bypass', label: '.NET bypass pack', hint: '.aspx / .cer handler confusion', defaultVal: true },
  { key: 'check_java_bypass', label: 'Java bypass pack', hint: '.jsp / .jspx MIME spoof', defaultVal: true },
  { key: 'check_node_bypass', label: 'Node static-exec surface', hint: '.js / .mjs uploaded to static paths', defaultVal: true },
  { key: 'check_null_byte', label: 'Null-byte legacy bypass', hint: 'shell.php%00.jpg (Aggressive)', defaultVal: false },
  { key: 'check_trailing_dot', label: 'Trailing dot/space', hint: 'Windows parser tricks (Aggressive)', defaultVal: false },
  { key: 'check_put_upload', label: 'HTTP PUT upload', hint: 'Direct object write bypass (Normal+)', defaultVal: true },
  { key: 'check_patch_upload', label: 'HTTP PATCH upload', hint: 'Partial object write (Aggressive)', defaultVal: false },
  { key: 'check_graphql_upload', label: 'GraphQL multipart', hint: 'Upload scalar transport probe', defaultVal: true },
  { key: 'check_base64_json', label: 'Base64 JSON API', hint: 'JSON wrapper {file:{content:base64}}', defaultVal: true },
  { key: 'check_zip_upload', label: 'ZIP / zip-slip surface', hint: 'Archive upload + inner path reflection', defaultVal: true },
  { key: 'verify_storage', label: 'Verify storage retrieval', hint: 'Fetch URL + confirm canary served back', defaultVal: true },
  { key: 'storage_path_oracle', label: 'Storage path oracle', hint: 'Brute /uploads /media /wp-content/uploads …', defaultVal: true },
  { key: 'check_openapi_discovery', label: 'OpenAPI discovery', hint: 'Parse swagger for multipart POST paths', defaultVal: true },
  { key: 'check_js_discovery', label: 'JS bundle discovery', hint: 'Harvest /upload URLs from JS bundles', defaultVal: true },
  { key: 'check_cms_paths', label: 'CMS / enterprise paths', hint: 'WordPress, Drupal, SharePoint, Strapi, Laravel FM…', defaultVal: true },
  { key: 'check_upload_idor', label: 'Upload IDOR oracle', hint: 'Probe sequential object IDs after upload', defaultVal: true },
  { key: 'check_tus_upload', label: 'Tus resumable upload', hint: 'Tus-Resumable: 1.0.0 creation probe (Normal+)', defaultVal: true },
  { key: 'check_webdav_discovery', label: 'WebDAV OPTIONS', hint: 'Allow/DAV headers on upload paths (Normal+)', defaultVal: true },
  { key: 'check_auth_differential', label: 'Auth differential', hint: 'Upload without session when creds supplied (Normal+)', defaultVal: true },
  { key: 'check_unicode_homoglyph', label: 'Unicode homoglyph', hint: 'Cyrillic а in .php extension (Normal+)', defaultVal: true },
  { key: 'check_multipart_hpp', label: 'Multipart HPP', hint: 'Dual file fields in one request (Normal+)', defaultVal: true },
  { key: 'check_content_range', label: 'Content-Range PUT', hint: 'Partial/resumable write via Content-Range (Normal+)', defaultVal: true },
  { key: 'check_directory_listing', label: 'Storage directory listing', hint: 'Index-of on /uploads /media roots', defaultVal: true },
  { key: 'check_presigned_probe', label: 'Presigned URL probe', hint: 'Extract S3/Azure/GCS presigned URLs from page', defaultVal: true },
  { key: 'check_size_limit_oracle', label: 'Size limit oracle', hint: '413 fingerprint at 16/64/256KB (Aggressive)', defaultVal: false },
  { key: 'check_unauth_retrieval', label: 'Unauth download', hint: 'Fetch uploaded URL without session after auth upload', defaultVal: true },
  { key: 'check_cdn_cache_isolation', label: 'CDN cache isolation', hint: 'public Cache-Control on retrieved uploads', defaultVal: true },
  { key: 'check_waf_fingerprint', label: 'WAF fingerprint', hint: '403 + Cloudflare/Akamai/Imperva signals', defaultVal: true },
  { key: 'check_robots_discovery', label: 'robots.txt hints', hint: 'Harvest upload paths from robots.txt', defaultVal: true },
  { key: 'check_url_encoded_extension', label: 'URL-encoded extension', hint: '.%70hp / p%68p bypass', defaultVal: true },
  { key: 'check_long_filename', label: 'Long filename stress', hint: '180-char name + .php.jpg', defaultVal: true },
  { key: 'check_jpeg_com_polyglot', label: 'JPEG COM polyglot', hint: 'COM marker comment canary in image/jpeg', defaultVal: true },
  { key: 'check_docx_surface', label: 'DOCX OOXML surface', hint: 'Mini ZIP-based DOCX acceptance', defaultVal: true },
  { key: 'check_crlf_filename_reflection', label: 'CRLF filename oracle', hint: 'CRLF in filename reflection (Aggressive)', defaultVal: false },
  { key: 'check_reverse_double_extension', label: 'Reverse double extension', hint: '.jpg.php / .gif.php parser confusion (Normal+)', defaultVal: true },
  { key: 'check_iis_handlers', label: 'IIS handler surface', hint: '.ashx / .asmx / .shtml MIME spoof (Normal+)', defaultVal: true },
  { key: 'check_template_injection_filename', label: 'SSTI filename oracle', hint: '{{7*7}}.txt reflection probe (Normal+)', defaultVal: true },
  { key: 'check_upload_cors', label: 'Upload CORS misconfig', hint: 'ACAO wildcard or reflected Origin on POST (Normal+)', defaultVal: true },
  { key: 'check_rate_limit_absence', label: 'Rate limit absence', hint: '6 rapid POSTs without HTTP 429 (Normal+)', defaultVal: true },
  { key: 'check_error_disclosure', label: 'Error disclosure', hint: 'Stack/path leak on malformed multipart (Normal+)', defaultVal: true },
  { key: 'check_delete_without_auth', label: 'Unauth DELETE', hint: 'DELETE stored object without session (Normal+)', defaultVal: true },
  { key: 'check_range_retrieval', label: 'Range byte leak', hint: 'HTTP 206 partial read of uploaded object', defaultVal: true },
  { key: 'check_sitemap_discovery', label: 'Sitemap discovery', hint: 'Harvest /upload paths from sitemap.xml', defaultVal: true },
  { key: 'check_spring_paths', label: 'Spring Boot paths', hint: '/api/file, /uploadFile, /api/v1/attachments…', defaultVal: true },
  { key: 'check_sharepoint_paths', label: 'SharePoint / Graph paths', hint: '/_layouts/15/upload.aspx, /_api/v2.1/drives/…', defaultVal: true },
  { key: 'check_eicar_surface', label: 'EICAR AV oracle', hint: 'Industry-standard AV test string — no malware (Normal+)', defaultVal: true },
  { key: 'check_batch_upload', label: 'Batch multi-file upload', hint: '3 files in one multipart request (Normal+)', defaultVal: true },
  { key: 'check_webp_png_surface', label: 'WebP / PNG surface', hint: 'Modern image format acceptance (Normal+)', defaultVal: true },
  { key: 'check_filename_field_mismatch', label: 'Filename field mismatch', hint: 'safe.jpg metadata + shell.php body (Normal+)', defaultVal: true },
  { key: 'check_double_content_disposition', label: 'Double Content-Disposition', hint: 'Two disposition headers in one part (Normal+)', defaultVal: true },
  { key: 'check_boundary_smuggling', label: 'Boundary smuggling', hint: 'Embedded boundary in part body (Aggressive)', defaultVal: false },
  { key: 'check_json_multi_file', label: 'JSON multi-file API', hint: '{files:[{name,content:base64}]} envelope (Normal+)', defaultVal: true },
  { key: 'check_imagemagick_surface', label: 'ImageMagick fingerprint', hint: 'Policy/delegate errors in SVG upload response', defaultVal: true },
  { key: 'check_svg_foreign_object', label: 'SVG foreignObject', hint: 'XHTML foreignObject XSS surface (Normal+)', defaultVal: true },
  { key: 'check_internal_url_disclosure', label: 'Internal URL disclosure', hint: '127.0.0.1 / localhost / metadata in JSON response', defaultVal: true },
  { key: 'check_semicolon_bypass', label: 'Semicolon mid-extension', hint: 'shell.php;.jpg Apache/IIS trick', defaultVal: true },
  { key: 'check_apache_multisuffix', label: 'Apache .php.foo suffix', hint: 'Multi-suffix parser confusion', defaultVal: true },
  { key: 'check_cloud_native_paths', label: 'Cloud-native paths', hint: 'Vercel/Firebase/Supabase/R2/SignalR upload APIs', defaultVal: true },
  { key: 'check_security_txt_discovery', label: 'security.txt hints', hint: 'Harvest upload URLs from /.well-known/security.txt', defaultVal: true },
  { key: 'check_gzip_upload', label: 'Gzip Content-Encoding', hint: 'gzip-compressed multipart body (Normal+)', defaultVal: true },
  { key: 'check_expect_continue', label: 'Expect: 100-continue', hint: 'HTTP continue flow on upload (Normal+)', defaultVal: true },
  { key: 'check_x_forwarded_host', label: 'X-Forwarded-Host reflection', hint: 'Host header reflected in response/Location', defaultVal: true },
  { key: 'check_location_header_leak', label: 'Location header leak', hint: 'Storage/bucket path in Location after upload', defaultVal: true },
  { key: 'check_overwrite_oracle', label: 'Overwrite oracle', hint: 'Same filename twice — version/stale retention', defaultVal: true },
  { key: 'check_head_metadata_leak', label: 'HEAD metadata leak', hint: 'Sequential ETag / x-amz-meta on stored object', defaultVal: true },
  { key: 'check_xlsm_surface', label: 'XLSM macro surface', hint: 'Macro-enabled OOXML workbook acceptance', defaultVal: true },
  { key: 'check_pdf_js_surface', label: 'PDF JS surface', hint: 'PDF container acceptance — JS stripping check', defaultVal: true },
  { key: 'check_rtlo_bypass', label: 'RTLO bidi bypass', hint: 'Right-to-left override in filename', defaultVal: true },
  { key: 'check_nfkc_bypass', label: 'NFKC fullwidth bypass', hint: 'Fullwidth .ｐｈｐ extension', defaultVal: true },
  { key: 'check_newline_extension', label: 'Newline in extension', hint: 'shell.php%0a.jpg (Aggressive)', defaultVal: false },
]

const STACK_PACKS = [
  { value: 'auto', label: 'Auto (fingerprint stack)' },
  { value: 'all', label: 'All platforms' },
  { value: 'php', label: 'PHP only' },
  { value: 'iis', label: 'IIS only' },
  { value: 'dotnet', label: '.NET only' },
  { value: 'java', label: 'Java only' },
  { value: 'node', label: 'Node only' },
]

const POSTURE_DIMS = [
  { key: 'extension_validation', label: 'Extension validation', color: '#fb923c' },
  { key: 'mime_validation', label: 'MIME validation', color: '#fbbf24' },
  { key: 'content_inspection', label: 'Content inspection', color: '#c084fc' },
  { key: 'storage_isolation', label: 'Storage isolation', color: '#38bdf8' },
  { key: 'config_upload_resistance', label: 'Config upload resistance', color: '#f87171' },
  { key: 'path_traversal_resistance', label: 'Path traversal resistance', color: '#a78bfa' },
  { key: 'platform_hardening', label: 'Platform hardening', color: '#e879f9' },
  { key: 'delivery_hardening', label: 'Delivery (nosniff)', color: '#34d399' },
  { key: 'cors_isolation', label: 'CORS isolation', color: '#22d3ee' },
  { key: 'authz_boundary', label: 'AuthZ boundary', color: '#fcd34d' },
  { key: 'object_id_entropy', label: 'Object ID entropy', color: '#f472b6' },
  { key: 'resumable_protocol_hygiene', label: 'Tus/resumable hygiene', color: '#67e8f9' },
  { key: 'anonymous_download', label: 'Anonymous download', color: '#f472b6' },
  { key: 'cache_isolation', label: 'CDN cache isolation', color: '#22d3ee' },
  { key: 'abuse_resilience', label: 'Abuse resilience', color: '#f97316' },
  { key: 'error_hygiene', label: 'Error hygiene', color: '#94a3b8' },
  { key: 'template_injection_surface', label: 'Template injection surface', color: '#ef4444' },
  { key: 'av_pipeline', label: 'AV pipeline', color: '#34d399' },
  { key: 'batch_upload_control', label: 'Batch upload control', color: '#f97316' },
  { key: 'parser_robustness', label: 'Parser robustness', color: '#a78bfa' },
  { key: 'path_entropy_quality', label: 'Path entropy', color: '#38bdf8' },
  { key: 'overwrite_protection', label: 'Overwrite protection', color: '#f472b6' },
  { key: 'host_header_isolation', label: 'Host header isolation', color: '#f97316' },
]

const CATEGORY_META = {
  posture_summary: { label: 'Posture Summary', icon: '◈', color: ACCENT, order: 0 },
  mime_spoof: { label: 'MIME Spoofing', icon: '🎭', color: '#fbbf24', order: 1 },
  double_extension: { label: 'Double Extension', icon: '⧉', color: '#fb923c', order: 2 },
  polyglot: { label: 'Polyglot', icon: '🔀', color: '#c084fc', order: 3 },
  path_traversal: { label: 'Path Traversal', icon: '📂', color: '#f87171', order: 4 },
  case_bypass: { label: 'Case Bypass', icon: 'Aa', color: '#a78bfa', order: 5 },
  svg_xss: { label: 'SVG XSS', icon: '⚠', color: '#ef4444', order: 6 },
  config_upload: { label: 'Config Upload', icon: '⚙', color: '#fb7185', order: 7 },
  null_byte: { label: 'Null Byte', icon: '∅', color: '#94a3b8', order: 8 },
  trailing_dot: { label: 'Trailing Dot', icon: '·', color: '#94a3b8', order: 9 },
  put_method: { label: 'PUT Upload', icon: '↑', color: '#38bdf8', order: 10 },
  patch_method: { label: 'PATCH Upload', icon: '↺', color: '#38bdf8', order: 11 },
  disposition_bypass: { label: 'Disposition Bypass', icon: '📎', color: '#f472b6', order: 12 },
  platform_php: { label: 'PHP Platform', icon: '🐘', color: '#818cf8', order: 13 },
  platform_iis: { label: 'IIS Platform', icon: '🪟', color: '#60a5fa', order: 14 },
  platform_dotnet: { label: '.NET Platform', icon: '◈', color: '#a78bfa', order: 15 },
  platform_java: { label: 'Java Platform', icon: '☕', color: '#fb7185', order: 16 },
  platform_node: { label: 'Node Platform', icon: '⬢', color: '#4ade80', order: 17 },
  base64_api: { label: 'Base64 JSON API', icon: '{ }', color: '#22d3ee', order: 18 },
  zip_slip_surface: { label: 'ZIP / Zip-Slip', icon: '🗜', color: '#fbbf24', order: 19 },
  upload_idor: { label: 'Upload IDOR', icon: '🔓', color: '#ef4444', order: 21 },
  tus_surface: { label: 'Tus / Resumable', icon: '⏩', color: '#22d3ee', order: 22 },
  webdav_surface: { label: 'WebDAV Surface', icon: '📁', color: '#94a3b8', order: 23 },
  auth_boundary: { label: 'Auth Boundary', icon: '🔐', color: '#fbbf24', order: 24 },
  unicode_homoglyph: { label: 'Unicode Homoglyph', icon: 'α', color: '#c084fc', order: 25 },
  multipart_hpp: { label: 'Multipart HPP', icon: '⧉', color: '#fb923c', order: 26 },
  content_range: { label: 'Content-Range', icon: '▥', color: '#38bdf8', order: 27 },
  directory_listing: { label: 'Directory Listing', icon: '📋', color: '#f87171', order: 28 },
  presigned_url: { label: 'Presigned URL', icon: '☁', color: '#60a5fa', order: 29 },
  size_limit_oracle: { label: 'Size Limit Oracle', icon: '⚖', color: '#94a3b8', order: 30 },
  endpoint_discovery: { label: 'Discovery', icon: '🔍', color: '#94a3b8', order: 31 },
  upload_cors: { label: 'Upload CORS', icon: '🌐', color: '#f97316', order: 32 },
  rate_limit_absence: { label: 'Rate Limit', icon: '⚡', color: '#fbbf24', order: 33 },
  error_disclosure: { label: 'Error Disclosure', icon: '⚠', color: '#94a3b8', order: 34 },
  template_injection: { label: 'SSTI Filename', icon: '{{', color: '#ef4444', order: 35 },
  reverse_double_extension: { label: 'Reverse Double-Ext', icon: '⧉', color: '#fb923c', order: 36 },
  iis_handlers: { label: 'IIS Handlers', icon: '🪟', color: '#60a5fa', order: 37 },
  delete_without_auth: { label: 'Unauth DELETE', icon: '🗑', color: '#f87171', order: 38 },
  range_retrieval_leak: { label: 'Range Leak', icon: '▥', color: '#38bdf8', order: 39 },
  mime_persistence: { label: 'MIME Persistence', icon: '🎭', color: '#fbbf24', order: 40 },
  oast_filename: { label: 'OAST Filename', icon: '📡', color: '#a78bfa', order: 41 },
  eicar_surface: { label: 'EICAR / AV Pipeline', icon: '🛡', color: '#34d399', order: 42 },
  batch_upload: { label: 'Batch Upload', icon: '📦', color: '#f97316', order: 43 },
  json_multi_file: { label: 'JSON Multi-File', icon: '{ }', color: '#22d3ee', order: 44 },
  filename_mismatch: { label: 'Filename Mismatch', icon: '≠', color: '#fb923c', order: 45 },
  double_disposition: { label: 'Double Disposition', icon: '⧉', color: '#f472b6', order: 46 },
  boundary_smuggling: { label: 'Boundary Smuggle', icon: '⌁', color: '#ef4444', order: 47 },
  svg_foreign_object: { label: 'SVG foreignObject', icon: '⚠', color: '#ef4444', order: 48 },
  modern_format: { label: 'WebP/PNG', icon: '🖼', color: '#38bdf8', order: 49 },
  imagemagick_surface: { label: 'ImageMagick', icon: '🪄', color: '#94a3b8', order: 50 },
  internal_url_disclosure: { label: 'Internal URL Leak', icon: '🔗', color: '#f87171', order: 51 },
  semicolon_bypass: { label: 'Semicolon Bypass', icon: ';', color: '#fb923c', order: 52 },
  apache_multisuffix: { label: 'Apache Multi-Suffix', icon: '·', color: '#fb923c', order: 53 },
  gzip_upload: { label: 'Gzip Upload', icon: '⧉', color: '#94a3b8', order: 54 },
  expect_continue: { label: 'Expect Continue', icon: '100', color: '#94a3b8', order: 55 },
  x_forwarded_host: { label: 'X-Forwarded-Host', icon: '⇄', color: '#f97316', order: 56 },
  location_header_leak: { label: 'Location Leak', icon: '→', color: '#f87171', order: 57 },
  overwrite_oracle: { label: 'Overwrite Oracle', icon: '↺', color: '#f472b6', order: 58 },
  head_metadata_leak: { label: 'HEAD Metadata', icon: '◎', color: '#94a3b8', order: 59 },
  xlsm_surface: { label: 'XLSM Macro', icon: '📊', color: '#ef4444', order: 60 },
  pdf_js_surface: { label: 'PDF JS Surface', icon: '📄', color: '#fbbf24', order: 61 },
  rtlo_bypass: { label: 'RTLO Bidi', icon: '◀', color: '#ef4444', order: 62 },
  nfkc_bypass: { label: 'NFKC Fullwidth', icon: 'Ａ', color: '#c084fc', order: 63 },
  newline_extension: { label: 'Newline Ext', icon: '↵', color: '#94a3b8', order: 64 },
  other: { label: 'Other', icon: '•', color: '#94a3b8', order: 99 },
}

const SEV_STYLE = {
  critical: { text: 'text-rose-300', bd: 'border-rose-500/40', bg: 'bg-rose-500/10', dot: '#fb7185' },
  high: { text: 'text-orange-300', bd: 'border-orange-500/40', bg: 'bg-orange-500/10', dot: '#fb923c' },
  medium: { text: 'text-amber-300', bd: 'border-amber-500/40', bg: 'bg-amber-500/10', dot: '#fbbf24' },
  low: { text: 'text-sky-300', bd: 'border-sky-500/40', bg: 'bg-sky-500/10', dot: '#38bdf8' },
  info: { text: 'text-[var(--text-secondary)]', bd: 'border-[var(--border-default)]', bg: 'bg-[var(--row-hover-bg)]', dot: '#94a3b8' },
}

const ATTACK_REFERENCE = [
  { id: 'Upload IDOR oracle', desc: 'Sequential file/media IDs — fetch adjacent objects after upload', sev: 'critical' },
  { id: 'Stack-aware packs', desc: 'PHP/IIS/.NET/Java/Node bypasses auto-selected from fingerprint', sev: 'critical' },
  { id: 'Tus resumable', desc: 'Tus-Resumable creation — chunked upload without multipart', sev: 'high' },
  { id: 'WebDAV OPTIONS', desc: 'PUT/DELETE/DAV on upload path — bypass app controls', sev: 'high' },
  { id: 'Unicode homoglyph', desc: 'Cyrillic а in extension — filter evasion', sev: 'critical' },
  { id: 'Blast-radius score', desc: 'Composite RCE/XSS/IDOR exposure index (0–100)', sev: 'critical' },
  { id: 'Presigned cloud PUT', desc: 'S3/Azure/GCS presigned URL extraction + reachability', sev: 'high' },
  { id: 'Ultra wave', desc: 'Reverse double-ext, IIS handlers, SSTI filename, CORS/rate-limit, DELETE/Range leak', sev: 'critical' },
  { id: 'Enterprise risk tier', desc: 'Catastrophic→Low composite from blast-radius + critical count', sev: 'critical' },
  { id: 'Omega wave', desc: 'EICAR AV oracle, batch upload, WebP/PNG, SharePoint paths, boundary smuggle, JSON multi-file', sev: 'critical' },
  { id: 'Apex wave', desc: 'RTLO/NFKC, cloud-native paths, gzip upload, overwrite oracle, path entropy + remediation urgency', sev: 'critical' },
]

function gradeColor(g) { return { A: '#34d399', B: '#a3e635', C: '#fbbf24', D: '#fb923c' }[g] || '#fb7185' }
function csvToArray(s) { return String(s || '').split(/[\n,]+/).map((x) => x.trim()).filter(Boolean) }
function isSummary(f) { return f && (f.category === 'posture_summary' || f.summary === true || typeof f.posture_score === 'number') }

function EvidenceView({ evidence }) {
  if (!evidence || typeof evidence !== 'object') return null
  const checks = Array.isArray(evidence.checks) ? evidence.checks : []
  const scalars = Object.entries(evidence).filter(([k]) => k !== 'checks')
  return (
    <div className="mt-2 rounded-lg bg-[var(--bg-2)] border border-[var(--border-subtle)] p-3 space-y-2">
      {scalars.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1">
          {scalars.map(([k, v]) => (
            <div key={k} className="flex items-start gap-2 text-[11px] font-mono">
              <span className="text-[var(--text-muted)] shrink-0">{k}</span>
              <span className="text-[var(--text-secondary)] break-all">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</span>
            </div>
          ))}
        </div>
      )}
      {checks.length > 0 && (
        <div className="space-y-1 pt-1 border-t border-[var(--border-subtle)]">
          {checks.map((c, i) => (
            <div key={i} className="flex items-center gap-2 text-[11px] font-mono">
              <span className={c.observed ? 'text-emerald-400' : 'text-[var(--text-disabled)]'}>{c.observed ? '✓' : '·'}</span>
              <span className="text-[var(--text-tertiary)]">{c.name}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function FindingCard({ f }) {
  const [open, setOpen] = useState(false)
  const sev = (f.severity || 'info').toLowerCase()
  const st = SEV_STYLE[sev] || SEV_STYLE.info
  const controls = Array.isArray(f.controls) ? f.controls : []
  return (
    <div className={`rounded-xl border ${st.bd} ${st.bg} p-3`}>
      <Button variant="unstyled" type="button" onClick={() => setOpen((o) => !o)} className="w-full text-left flex items-start gap-3">
        <span className="mt-1 w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: st.dot }} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`text-[10px] font-mono uppercase tracking-wider ${st.text}`}>{sev}</span>
            {f.mitre_attack && <span className="text-[10px] font-mono text-[var(--text-disabled)]">· {f.mitre_attack}</span>}
          </div>
          <div className="text-sm text-[var(--text-primary)] font-medium mt-0.5">{f.title || f.type}</div>
        </div>
        <span className="text-[var(--text-disabled)] text-xs mt-1">{open ? '▾' : '▸'}</span>
      </Button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
            <p className="text-xs text-[var(--text-tertiary)] leading-relaxed mt-2">{f.description}</p>
            {f.remediation && (
              <div className="mt-2 rounded-lg bg-emerald-500/5 border border-emerald-500/20 p-2.5">
                <div className="text-[10px] font-mono uppercase text-emerald-400/70 mb-1">Remediation</div>
                <p className="text-[11px] text-emerald-100/80 leading-relaxed">{f.remediation}</p>
              </div>
            )}
            {controls.length > 0 && (
              <div className="flex flex-wrap gap-1.5 mt-2">
                {controls.map((c) => (
                  <span key={c} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--row-hover-bg)] text-[var(--text-tertiary)] border border-[var(--border-default)]">{c}</span>
                ))}
              </div>
            )}
            <EvidenceView evidence={f.evidence} />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

function Scorecard({ summary, t }) {
  if (!summary) return null
  const score = summary.posture_score ?? summary.evidence?.posture_score ?? 100
  const grade = summary.grade ?? summary.evidence?.grade ?? 'A'
  const color = gradeColor(grade)
  const ev = summary.evidence || {}
  const cats = summary.weak_categories || ev.weak_categories || []
  const dims = summary.posture_dimensions || ev.posture_dimensions || {}
  const paths = summary.attack_paths || ev.attack_paths || []
  const toxic = summary.toxic_combinations || ev.toxic_combinations || []
  const coverage = summary.probe_coverage || ev.probe_coverage
  const roadmap = Array.isArray(summary.hardening_roadmap) ? summary.hardening_roadmap : []
  const endpoints = ev.endpoints_discovered ?? summary.evidence?.endpoints_discovered
  const stack = summary.stack_fingerprint || ev.stack_fingerprint || []
  const blast = summary.blast_radius_score ?? ev.blast_radius_score
  const enterpriseTier = summary.enterprise_risk_tier ?? ev.enterprise_risk_tier
  const pathEntropy = summary.path_entropy_score ?? ev.path_entropy_score
  const remediationUrgency = summary.remediation_urgency ?? ev.remediation_urgency
  const tierColor = { Catastrophic: '#ef4444', Severe: '#fb923c', Elevated: '#fbbf24', Moderate: '#38bdf8', Low: '#34d399' }[enterpriseTier] || '#94a3b8'
  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-6 mb-6">
      <div className="flex flex-col lg:flex-row gap-6">
        <div className="flex items-center gap-5 shrink-0">
          <div className="relative w-28 h-28 shrink-0">
            <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
              <circle cx="50" cy="50" r="44" fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="8" />
              <circle cx="50" cy="50" r="44" fill="none" stroke={color} strokeWidth="8" strokeLinecap="round" strokeDasharray={`${(score / 100) * 276.46} 276.46`} />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-3xl font-bold" style={{ color }}>{score}</span>
              <span className="text-[10px] font-mono text-[var(--text-muted)]">/ 100</span>
            </div>
          </div>
          <div>
            <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)]">{t('pages.fileUploadLab.upload_posture', 'Upload Posture')}</div>
            <div className="text-5xl font-black leading-none" style={{ color }}>{grade}</div>
            {endpoints != null && (
              <div className="mt-1.5 text-[10px] font-mono text-[var(--text-muted)]">{endpoints} endpoint(s) probed</div>
            )}
            {blast != null && (
              <div className="mt-1 text-[10px] font-mono text-rose-300/90">Blast radius: {blast}/100</div>
            )}
            {enterpriseTier && (
              <div className="mt-1 text-[10px] font-mono font-bold" style={{ color: tierColor }}>Enterprise risk: {enterpriseTier}</div>
            )}
            {remediationUrgency != null && (
              <div className="mt-1 text-[10px] font-mono text-rose-300/80">Remediation urgency: {remediationUrgency}/100</div>
            )}
            {pathEntropy != null && (
              <div className="mt-1 text-[10px] font-mono text-sky-300/80">Path entropy: {pathEntropy}/100</div>
            )}
            {Array.isArray(stack) && stack.length > 0 && (
              <div className="mt-1 flex flex-wrap gap-1">
                {stack.map((s) => (
                  <span key={s} className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-orange-500/10 border border-orange-500/20 text-orange-200/80">{s}</span>
                ))}
              </div>
            )}
          </div>
        </div>
        <div className="flex-1 space-y-4">
          <div>
            <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2">{t('pages.fileUploadLab.posture_dimensions', 'Posture dimensions')}</div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {POSTURE_DIMS.map((d) => {
                const raw = dims[d.key]
                if (raw === undefined || raw === null) return null
                const n = Number(raw)
                const barColor = n >= 80 ? '#34d399' : n >= 60 ? '#fbbf24' : '#fb7185'
                return (
                  <div key={d.key} className="rounded-lg border border-[var(--border-subtle)] bg-[var(--table-surface)] px-2.5 py-2">
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <span className="text-[10px] font-mono text-[var(--text-tertiary)]">{d.label}</span>
                      <span className="text-[10px] font-mono font-bold" style={{ color: barColor }}>{n}</span>
                    </div>
                    <div className="h-1 rounded-full bg-[var(--row-hover-bg)] overflow-hidden">
                      <div className="h-full rounded-full" style={{ width: `${n}%`, backgroundColor: barColor }} />
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      </div>
      {paths.length > 0 && (
        <div className="mt-4 pt-4 border-t border-[var(--border-subtle)]">
          <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2">{t('pages.fileUploadLab.attack_paths', 'Attack paths')}</div>
          <div className="space-y-2">
            {paths.map((p, i) => (
              <div key={i} className="rounded-lg border border-orange-500/20 bg-orange-500/5 px-3 py-2">
                <div className="text-[11px] font-mono text-orange-300 font-bold">{p.title}</div>
                {Array.isArray(p.stages) && (
                  <div className="text-[10px] font-mono text-[var(--text-muted)] mt-1">{p.stages.join(' → ')}</div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
      {toxic.length > 0 && (
        <div className="mt-4 pt-4 border-t border-rose-500/20">
          <div className="text-[10px] font-mono uppercase tracking-wider text-rose-400/80 mb-2">{t('pages.fileUploadLab.toxic_combinations', 'Toxic combinations')}</div>
          <div className="space-y-2">
            {toxic.map((tx, i) => (
              <div role="alert" key={i} className="rounded-lg border border-rose-500/30 bg-rose-950/20 px-3 py-2">
                <div className="text-[11px] font-mono text-rose-300 font-bold">{tx.name}</div>
                <div className="text-[10px] font-mono text-[var(--text-tertiary)] mt-1">{tx.rationale}</div>
              </div>
            ))}
          </div>
        </div>
      )}
      {coverage && (
        <div className="mt-4 pt-4 border-t border-[var(--border-subtle)]">
          <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2">{t('pages.fileUploadLab.probe_coverage', 'Probe coverage manifest')}</div>
          <pre className="text-[10px] font-mono text-[var(--text-muted)] bg-[var(--bg-2)] rounded-lg p-3 overflow-x-auto max-h-40">{JSON.stringify(coverage, null, 2)}</pre>
        </div>
      )}
      {roadmap.length > 0 && (
        <div className="mt-4 pt-4 border-t border-[var(--border-subtle)]">
          <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2">{t('pages.fileUploadLab.hardening_roadmap', 'Hardening roadmap')}</div>
          <ol className="space-y-1">
            {roadmap.map((r, i) => (
              <li key={i} className="flex items-start gap-2 text-[11px] font-mono text-[var(--text-tertiary)]">
                <span className="text-orange-400">{i + 1}.</span>{r}
              </li>
            ))}
          </ol>
        </div>
      )}
      {cats.length > 0 && (
        <div className="mt-4 pt-4 border-t border-[var(--border-subtle)] flex flex-wrap items-center gap-2">
          <span className="text-[10px] font-mono text-[var(--text-muted)]">{t('pages.fileUploadLab.weak_areas', 'Weak areas:')}</span>
          {cats.map((c) => (
            <span key={c} className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-[var(--row-hover-bg)] border border-[var(--border-default)] text-[var(--text-tertiary)]">
              {(CATEGORY_META[c] || CATEGORY_META.other).icon} {(CATEGORY_META[c] || CATEGORY_META.other).label}
            </span>
          ))}
        </div>
      )}
    </motion.div>
  )
}

export default function FileUploadSecurityLab() {
  const { t } = useTranslation()
  const [clients, setClients] = useState([])
  const [clientId, setClientId] = useState('')
  const { postScan } = useCommandCenterScan(clientId)
  const [target, setTarget] = useState('')
  const [targetTouched, setTargetTouched] = useState(false)
  const [showParams, setShowParams] = useState(false)
  const [status, setStatus] = useState('idle')
  const [findings, setFindings] = useState([])
  const [pendingJobId, setPendingJobId] = useState(null)
  const [lastRun, setLastRun] = useState(null)
  const [toast, setToast] = useState(null)

  const [toggles, setToggles] = useState(() => Object.fromEntries(TOGGLES.map((tg) => [tg.key, tg.defaultVal])))
  const [intensity, setIntensity] = useState('normal')
  const [uploadPaths, setUploadPaths] = useState('/upload\n/api/upload\n/files/upload')
  const [extraEndpoints, setExtraEndpoints] = useState('')
  const [fieldNames, setFieldNames] = useState('file, upload, document')
  const [authCookie, setAuthCookie] = useState('')
  const [authHeader, setAuthHeader] = useState('')
  const [canaryToken, setCanaryToken] = useState('')
  const [oastHost, setOastHost] = useState('')
  const [timeoutMs, setTimeoutMs] = useState(8000)
  const [concurrency, setConcurrency] = useState(12)
  const [stackPack, setStackPack] = useState('auto')
  const [maxCombos, setMaxCombos] = useState(42)
  const [maxEndpoints, setMaxEndpoints] = useState(32)
  const [includeInfo, setIncludeInfo] = useState(true)

  const detailFindings = useMemo(() => findings.filter((f) => !isSummary(f)), [findings])

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
    // eslint-disable-next-line no-restricted-syntax -- intentional best-effort swallow
    apiFetch('/api/clients').then((d) => { if (Array.isArray(d)) setClients(d) }).catch(() => {})
  }, [])

  const selectedClient = useMemo(() => clients.find((c) => String(c.id) === String(clientId)), [clients, clientId])
  useEffect(() => { if (!targetTouched) setTarget(firstClientTarget(selectedClient)) }, [selectedClient, targetTouched])

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
      if (job?.id) setLastJobId(String(job.id))
      setPendingJobId(null)
    },
  })

  const buildBody = useCallback(() => {
    const body = {
      engine: ENGINE,
      target: target.trim().startsWith('http') ? target.trim() : `https://${target.trim()}`,
      ...toggles,
      intensity,
      include_info_findings: includeInfo,
      timeout_ms: Number(timeoutMs) || 8000,
      concurrency: Number(concurrency) || 12,
      max_endpoints: Number(maxEndpoints) || 32,
      max_combos_per_endpoint: Number(maxCombos) || 42,
      stack_pack: stackPack,
      upload_paths: csvToArray(uploadPaths),
      field_names: csvToArray(fieldNames),
    }
    if (clientId) body.client_id = Number(clientId)
    const ee = csvToArray(extraEndpoints)
    if (ee.length) body.extra_endpoints = ee
    if (authCookie.trim()) body.auth_cookie = authCookie.trim()
    if (authHeader.trim()) body.auth_header = authHeader.trim()
    if (canaryToken.trim()) body.canary_token = canaryToken.trim()
    if (oastHost.trim()) body.oast_host = oastHost.trim()
    return body
  }, [target, toggles, intensity, includeInfo, timeoutMs, concurrency, maxEndpoints, maxCombos, stackPack, uploadPaths, fieldNames, extraEndpoints, authCookie, authHeader, canaryToken, oastHost, clientId])

  const hubScanParams = useMemo(() => {
    const { engine, target, client_id, ...rest } = buildBody()
    return rest
  }, [buildBody])
  useSyncHubScanParams(ENGINE, hubScanParams)

  const handleRun = useCallback(async () => {
    if (!clientId) { showToast('error', t('pages.fileUploadLab.select_client_first', 'Select a client first')); return }
    if (!target.trim()) { showToast('error', t('pages.fileUploadLab.target_required', 'A target URL is required')); return }
    setStatus('running'); setFindings([])
    try {
      const { ok, data: d } = await postScan(buildBody())
      if (!ok) { setStatus('error'); showToast('error', d.detail || t('pages.fileUploadLab.scan_failed', 'Scan failed')); return }
      const jobId = d.job_id ?? ''
      showToast('info', t('pages.fileUploadLab.queued', 'Upload scan queued ({{jobId}})', { jobId }))
      if (jobId) setPendingJobId(jobId); else setStatus('error')
    } catch (e) {
      setStatus('error'); showToast('error', e?.message ?? t('pages.fileUploadLab.scan_failed', 'Scan failed'))
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clientId, target, buildBody, showToast, t])

  const summary = useMemo(() => findings.find(isSummary), [findings])
  const statusColor = { idle: '#475569', running: ACCENT, completed: '#4ade80', error: '#ef4444' }[status]

  return (
    <PageShell
      hideHubParams
      title={t('pages.fileUploadLab.title', 'File Upload Security Lab')}
      badge={t('pages.fileUploadLab.badge', 'UNRESTRICTED UPLOAD / RCE')}
      badgeColor={ACCENT}
      subtitle={t('pages.fileUploadLab.subtitle', 'Apex-grade upload arsenal: RTLO/NFKC bypass, cloud-native paths (Vercel/Firebase/R2), gzip/Expect-continue, overwrite oracle, path entropy + remediation urgency, XLSM/PDF-JS surfaces — plus full Omega/Ultra wave. 23-dimension posture, enterprise risk tier — benign canaries, evidence only.')}
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
            <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">{t('pages.fileUploadLab.client', 'Client')}</label>
            <BoundClientScanField
              clients={clients}
              selectedClientId={clientId}
              onChange={(id) => { setClientId(id || ''); setTargetTouched(false) }}
              emptyLabel={t('pages.fileUploadLab.select_client', '— Select client —')}
            />
          </div>
          <div className="flex flex-col gap-1 flex-1 min-w-[220px]">
            <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">{t('pages.fileUploadLab.target_url', 'Target URL')}</label>
            <input type="text" value={target} onChange={(e) => { setTarget(e.target.value); setTargetTouched(true) }} placeholder="https://example.com"
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-orange-500/40" />
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">{t('pages.fileUploadLab.intensity', 'Intensity')}</label>
            <select value={intensity} onChange={(e) => setIntensity(e.target.value)}
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-orange-500/40">
              <option value="light">{t('pages.fileUploadLab.intensity_light', 'Light')}</option>
              <option value="normal">{t('pages.fileUploadLab.intensity_normal', 'Normal')}</option>
              <option value="aggressive">{t('pages.fileUploadLab.intensity_aggressive', 'Aggressive')}</option>
            </select>
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">{t('pages.fileUploadLab.stack_pack', 'Platform pack')}</label>
            <select value={stackPack} onChange={(e) => setStackPack(e.target.value)}
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-orange-500/40">
              {STACK_PACKS.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
            </select>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full" style={{ backgroundColor: statusColor, boxShadow: status === 'running' ? `0 0 6px ${ACCENT}` : 'none' }} />
            <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase">{status}{lastRun ? ` · ${lastRun}` : ''}</span>
          </div>
          <Button variant="unstyled" type="button" onClick={handleRun} disabled={status === 'running' || !clientId}
            className="px-5 py-2 rounded-xl font-mono text-sm border border-orange-500/40 text-orange-300 bg-orange-500/10 hover:bg-orange-500/20 transition-all disabled:opacity-40 disabled:cursor-not-allowed">
            {status === 'running' ? t('pages.fileUploadLab.scanning', '⟳ Scanning…') : t('pages.fileUploadLab.run_scan', '▶ Run Upload Scan')}
          </Button>
          <Button variant="unstyled" type="button" onClick={() => setShowParams((s) => !s)}
            className="px-3 py-2 rounded-xl font-mono text-xs border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-[var(--text-secondary)] hover:border-[var(--border-strong)] transition-all">
            {showParams ? t('pages.fileUploadLab.hide_params', '▾ Parameters') : t('pages.fileUploadLab.show_params', '▸ Parameters')}
          </Button>
        </div>

        <AnimatePresence initial={false}>
          {showParams && (
            <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
              <div className="mt-5 pt-5 border-t border-[var(--border-subtle)] grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="space-y-2">
                  <p className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-2">{t('pages.fileUploadLab.bypass_matrix', 'Bypass matrix')}</p>
                  {TOGGLES.map((tg) => (
                    // eslint-disable-next-line jsx-a11y/label-has-associated-control -- label nests its checkbox control; text comes from dynamic {tg.label} which the rule cannot statically verify
                    <label key={tg.key} className="flex items-center justify-between gap-2 px-2 py-1.5 rounded-lg bg-[var(--row-hover-bg)] border border-[var(--border-subtle)] cursor-pointer hover:bg-[var(--row-hover-bg)]">
                      <span className="min-w-0">
                        <span className="block text-[11px] font-mono text-[var(--text-secondary)]">{tg.label}</span>
                        <span className="block text-[10px] font-mono text-[var(--text-muted)] truncate">{tg.hint}</span>
                      </span>
                      <input type="checkbox" checked={toggles[tg.key]} onChange={(e) => setToggles((prev) => ({ ...prev, [tg.key]: e.target.checked }))} className="accent-orange-500 shrink-0" />
                    </label>
                  ))}
                </div>
                <div className="space-y-3">
                  <label className="block">
                    <span className="text-[10px] font-mono uppercase text-[var(--text-muted)]">{t('pages.fileUploadLab.upload_paths', 'Upload paths')}</span>
                    <textarea value={uploadPaths} onChange={(e) => setUploadPaths(e.target.value)} rows={5}
                      className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-md px-2 py-1.5 text-[11px] font-mono text-[var(--text-secondary)] focus:outline-none focus:border-orange-500/40 resize-y" />
                  </label>
                  <label className="block">
                    <span className="text-[10px] font-mono uppercase text-[var(--text-muted)]">{t('pages.fileUploadLab.field_names', 'Field names')}</span>
                    <input value={fieldNames} onChange={(e) => setFieldNames(e.target.value)}
                      className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-md px-2 py-1.5 text-[11px] font-mono text-[var(--text-secondary)] focus:outline-none focus:border-orange-500/40" />
                  </label>
                  <label className="block">
                    <span className="text-[10px] font-mono uppercase text-[var(--text-muted)]">{t('pages.fileUploadLab.extra_endpoints', 'Extra endpoints')}</span>
                    <textarea value={extraEndpoints} onChange={(e) => setExtraEndpoints(e.target.value)} rows={2} placeholder="https://example.com/custom/upload"
                      className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-md px-2 py-1.5 text-[11px] font-mono text-[var(--text-secondary)] focus:outline-none focus:border-orange-500/40 resize-y" />
                  </label>
                </div>
                <div className="space-y-3">
                  <label className="block">
                    <span className="text-[10px] font-mono uppercase text-[var(--text-muted)]">{t('pages.fileUploadLab.auth_cookie', 'Session cookie')}</span>
                    <input value={authCookie} onChange={(e) => setAuthCookie(e.target.value)} placeholder="session=..."
                      className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-md px-2 py-1.5 text-[11px] font-mono text-[var(--text-secondary)] focus:outline-none focus:border-orange-500/40" />
                  </label>
                  <label className="block">
                    <span className="text-[10px] font-mono uppercase text-[var(--text-muted)]">{t('pages.fileUploadLab.auth_header', 'Authorization header')}</span>
                    <input value={authHeader} onChange={(e) => setAuthHeader(e.target.value)} placeholder="Bearer ..."
                      className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-md px-2 py-1.5 text-[11px] font-mono text-[var(--text-secondary)] focus:outline-none focus:border-orange-500/40" />
                  </label>
                  <label className="block">
                    <span className="text-[10px] font-mono uppercase text-[var(--text-muted)]">{t('pages.fileUploadLab.canary_token', 'Canary token')}</span>
                    <input value={canaryToken} onChange={(e) => setCanaryToken(e.target.value)} placeholder="WZUPLOAD9137BENIGN"
                      className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-md px-2 py-1.5 text-[11px] font-mono text-[var(--text-secondary)] focus:outline-none focus:border-orange-500/40" />
                  </label>
                  <label className="block">
                    <span className="text-[10px] font-mono uppercase text-[var(--text-muted)]">{t('pages.fileUploadLab.oast_host', 'OAST callback host (optional)')}</span>
                    <input value={oastHost} onChange={(e) => setOastHost(e.target.value)} placeholder="your-id.oast.example.com"
                      className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-md px-2 py-1.5 text-[11px] font-mono text-[var(--text-secondary)] focus:outline-none focus:border-orange-500/40" />
                  </label>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                    <label className="block">
                      <span className="text-[10px] font-mono uppercase text-[var(--text-muted)]">Timeout ms</span>
                      <input type="number" value={timeoutMs} onChange={(e) => setTimeoutMs(e.target.value)}
                        className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-md px-2 py-1 text-[11px] font-mono text-[var(--text-secondary)]" />
                    </label>
                    <label className="block">
                      <span className="text-[10px] font-mono uppercase text-[var(--text-muted)]">Concurrency</span>
                      <input type="number" value={concurrency} onChange={(e) => setConcurrency(e.target.value)}
                        className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-md px-2 py-1 text-[11px] font-mono text-[var(--text-secondary)]" />
                    </label>
                    <label className="block">
                      <span className="text-[10px] font-mono uppercase text-[var(--text-muted)]">Max endpoints</span>
                      <input type="number" value={maxEndpoints} onChange={(e) => setMaxEndpoints(e.target.value)}
                        className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-md px-2 py-1 text-[11px] font-mono text-[var(--text-secondary)]" />
                    </label>
                    <label className="block">
                      <span className="text-[10px] font-mono uppercase text-[var(--text-muted)]">Max combos</span>
                      <input type="number" value={maxCombos} onChange={(e) => setMaxCombos(e.target.value)}
                        className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-md px-2 py-1 text-[11px] font-mono text-[var(--text-secondary)]" />
                    </label>
                  </div>
                  <label className="flex items-center gap-2 text-[11px] font-mono text-[var(--text-tertiary)] cursor-pointer">
                    <input type="checkbox" checked={includeInfo} onChange={(e) => setIncludeInfo(e.target.checked)} className="accent-orange-500" />
                    {t('pages.fileUploadLab.include_info', 'Include info-level discovery findings')}
                  </label>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 mb-6">
        <div className="lg:col-span-1 rounded-2xl bg-[var(--table-surface)] border border-[var(--border-default)] p-4">
          <p className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-3">{t('pages.fileUploadLab.attack_reference', 'Attack reference')}</p>
          <div className="space-y-2">
            {ATTACK_REFERENCE.map((a) => (
              <div key={a.id} className="rounded-lg border border-[var(--border-subtle)] bg-[var(--table-surface)] px-2.5 py-2">
                <div className="text-[10px] font-mono text-orange-300">{a.id}</div>
                <div className="text-[10px] font-mono text-[var(--text-tertiary)] mt-0.5">{a.desc}</div>
              </div>
            ))}
          </div>
        </div>
        <div className="lg:col-span-3">
          <Scorecard summary={summary} t={t} />
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
            emptyReadyTitle={t('pages.fileUploadLab.empty_ready', 'Run an upload scan to assess bypass resistance.')}
            emptyReadyBody={t('pages.fileUploadLab.no_findings', 'No upload vulnerabilities verified — posture is strong or endpoints not reachable.')}
            renderFinding={(f, i) => <FindingCard key={i} f={f} />}
          />
        </div>
      </div>
    </PageShell>
  )
}
