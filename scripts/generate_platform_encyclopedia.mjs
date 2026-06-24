#!/usr/bin/env node
/**
 * Weissman Platform Encyclopedia — full coverage + CEO-grade HTML viewer.
 * Outputs:
 *   docs/sales/WEISSMAN-PLATFORM-ENCYCLOPEDIA.md
 *   docs/sales/viewer/index.html
 *   docs/sales/viewer/data.json
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import {
  INTRO_PAGES,
  PLATFORM_MODULES,
  ROUTE_META,
  ROUTE_TITLES,
  GROUP_DEFAULTS,
  GROUP_HE,
  EXTRA_SURFACES,
  API_DOMAIN_PAGES,
} from './platform_page_catalog.mjs'
import {
  buildRouteIntelMap,
  parseHttpApiRoutes,
  groupApiRoutes,
} from './extract_route_intel.mjs'

const root = process.cwd()
const heNav = JSON.parse(readFileSync(join(root, 'frontend/src/i18n/locales/he.json'), 'utf8')).nav
const mainJsx = readFileSync(join(root, 'frontend/src/main.jsx'), 'utf8')
const appNavSrc = readFileSync(join(root, 'frontend/src/lib/appNav.js'), 'utf8')
const routeEngineSrc = readFileSync(join(root, 'frontend/src/lib/routeEngineId.js'), 'utf8')
const enginesSrc = readFileSync(join(root, 'frontend/src/lib/enginesRegistry.js'), 'utf8')
const routeIntel = buildRouteIntelMap()

const AGENT_REQUIRED = new Set([
  'process_hollowing', 'dll_hijacking_engine', 'process_inventory', 'av_bypass_engine',
  'log_tampering_engine', 'anti_debug_evasion', 'rootkit_simulation', 'memory_forensics_evasion',
  'usb_enumeration', 'dns_tunneling_c2', 'icmp_covert', 'bootkit_uefi', 'persistence_mechanism',
  'polymorphic_engine', 'ransomware_emulation', 'acoustic_exfil', 'em_exfil_engine', 'optical_exfil',
  'keyboard_acoustic', 'screen_capture_exfil', 'clipboard_hijack', 'insider_exfil',
  'storage_covert_channel', 'arp_spoofing_engine', 'vlan_hopping_attack', 'dhcp_attack_engine',
  'wifi_attack_engine', 'bluetooth_attack_engine', 'lte_5g_attack', 'wpa3_attack_engine',
  'packet_injection_engine', 'network_tap_advanced', 'multicast_attack', 'nat_traversal_attack',
  'sim_swap_engine', 'bluetooth_mobile_attack', 'nfc_relay_attack', 'deepfake_voice_engine',
  'pretexting_engine', 'insider_threat_engine', 'physical_social_eng', 'lorawan_attack',
  'lora_attack', 'voltage_glitch_attack', 'tpm_firmware_attack', 'cold_boot_attack',
  'infostealer_emulation',
])

function pad(n) {
  return String(n).padStart(3, '0')
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

function parseRoutes() {
  const re = /path="([^"]+)"/g
  const seen = new Set()
  const routes = []
  let m
  while ((m = re.exec(mainJsx))) {
    const p = m[1]
    if (p === '*' || (p.startsWith('/') && p !== '/')) continue
    if (seen.has(p)) continue
    seen.add(p)
    routes.push(p)
  }
  if (!seen.has('login')) routes.push('login')
  if (!seen.has('status')) routes.push('status')
  return routes.sort((a, b) => {
    if (a === '/') return -1
    if (b === '/') return 1
    return a.localeCompare(b)
  })
}

function parseRouteEngineMap() {
  const map = {}
  for (const m of routeEngineSrc.matchAll(/'([^']+)':\s*'([^']+)'/g)) {
    if (m[1].startsWith('/')) map[m[1].slice(1)] = m[2]
  }
  return map
}

function buildNavIndex() {
  const items = []
  const addFromBlock = (block, gid) => {
    if (!block) return
    for (const im of block.matchAll(/to:\s*'([^']+)'[\s\S]*?labelKey:\s*'nav\.([^']+)'/g)) {
      items.push({ to: im[1], gid, labelKey: im[2] })
    }
  }
  addFromBlock(appNavSrc.match(/export const PRIMARY_NAV = \[([\s\S]*?)\n\]/)?.[1], 'primary')
  for (const g of appNavSrc.matchAll(
    /\{\s*\n\s*id:\s*'(\w+)'[\s\S]*?\n\s*items:\s*\[([\s\S]*?)\n\s*\],?\n\s*\}/g,
  )) {
    addFromBlock(g[2], g[1])
  }
  return items.sort((a, b) => b.to.length - a.to.length)
}

const NAV_INDEX = buildNavIndex()

function matchNav(route) {
  const path = route === '/' ? '/' : `/${route.replace(/\/$/, '')}`
  for (const item of NAV_INDEX) {
    if (item.to === path) return item
    if (item.to !== '/' && (path === item.to || path.startsWith(`${item.to}/`))) return item
  }
  return null
}

function navLabelForRoute(route) {
  const m = matchNav(route)
  return m ? heNav[m.labelKey] || m.labelKey : null
}

function navGroupForRoute(route) {
  return matchNav(route)?.gid || 'engines'
}

function routeKey(route) {
  if (route === '/') return '/'
  return route.replace(/^\//, '')
}

function buildRichWhat(title, intel, engines, descriptions) {
  const parts = []
  if (descriptions.length) {
    parts.push(
      descriptions
        .slice(0, 4)
        .map((d) => `**${d.id}**: ${d.text}`)
        .join(' · '),
    )
  } else if (engines.length) {
    parts.push(`מנועים: ${engines.map((e) => `\`${e}\``).join(', ')}`)
  }
  if (intel.apis?.length) {
    parts.push(`${intel.apis.length} API endpoints חיים`)
  }
  if (intel.component) parts.push(`רכיב: \`${intel.component}\``)
  if (!parts.length) return `${title} — לוח Command Center עם נתוני אבטחה חיים, evidence, refresh, export.`
  return `${title} — ${parts.join(' · ')}`
}

function buildRoutePage(route, engineMap) {
  const key = routeKey(route)
  const meta = ROUTE_META[key] || {}
  const intel = routeIntel[route] || routeIntel[key] || {}
  const gid = navGroupForRoute(route === '/' ? '/' : `/${route}`)
  const defs = GROUP_DEFAULTS[gid] || GROUP_DEFAULTS.engines
  const navTitle =
    meta.title ||
    ROUTE_TITLES[key] ||
    navLabelForRoute(route) ||
    key.replace(/:\w+/g, (p) => ` (${p.slice(1)})`)
  const url =
    route === 'login'
      ? '/command-center/login'
      : route === 'status'
        ? '/command-center/status'
        : route === '/'
          ? '/command-center/'
          : `/command-center/${route.replace(/^\//, '')}`

  const engineList = [
    ...(meta.engines ? meta.engines.split(',').map((s) => s.trim()) : []),
    ...(intel.engines || []),
    engineMap[`/${key.split('/')[0]}`],
  ].filter(Boolean)
  const engines = [...new Set(engineList)]

  const apis =
    meta.apis ||
    (intel.apis?.length ? intel.apis.slice(0, 12).join(' · ') + (intel.apis.length > 12 ? ` · (+${intel.apis.length - 12})` : '') : null)

  const what =
    meta.what || buildRichWhat(navTitle, intel, engines, intel.descriptions || [])
  const why = meta.why || defs.why
  const when =
    meta.when ||
    (engines.some((e) => AGENT_REQUIRED.has(e))
      ? 'לאחר התקנת Agent online על ה-endpoint.'
      : 'במסגרת engagement מורשה, לאחר הגדרת client ו-scope.')
  const where = meta.where || url
  const how =
    meta.how ||
    (engines.length
      ? `1. בחר client · 2. ${navTitle} → Run (${engines[0]}) · 3. Jobs → Findings · 4. Export`
      : `ניווט: ${defs.group} → ${navTitle} → client → Refresh/Export`)
  const howMuch =
    meta.howMuch ||
    (engines.length
      ? `${engines.length} מנוע(ים) · 1 quota/run · ${engines.some((e) => AGENT_REQUIRED.has(e)) ? 'Agent חובה' : 'Remote'}`
      : `${intel.apis?.length || '—'} APIs`)
  const who = meta.who || defs.who
  const output = meta.output || 'findings + evidence + exports'

  return {
    kind: 'route',
    route: key,
    title: navTitle,
    group: meta.group || defs.group,
    what,
    why,
    when,
    where,
    how,
    howMuch,
    who,
    output,
    apis: apis || '—',
    engines: engines.length ? engines.join(', ') : null,
    component: intel.component || null,
  }
}

function parseEngines() {
  const re =
    /id:\s*'([^']+)'[\s\S]*?label:\s*'([^']+)'[\s\S]*?group:\s*'([^']+)'[\s\S]*?mitre:\s*'([^']*)'[\s\S]*?description:\s*'([^']*)'[\s\S]*?requiresTarget:\s*(true|false)/g
  const engines = []
  let m
  while ((m = re.exec(enginesSrc))) {
    engines.push({
      id: m[1],
      label: m[2],
      group: m[3],
      mitre: m[4],
      description: m[5],
      requiresTarget: m[6] === 'true',
      agent: AGENT_REQUIRED.has(m[1]),
    })
  }
  return engines
}

function buildApiDomainPages() {
  const all = parseHttpApiRoutes()
  const grouped = groupApiRoutes(all)
  const pages = []

  for (const domain of API_DOMAIN_PAGES) {
    const matched = all.filter((r) => domain.prefixes.some((p) => r.path.startsWith(p)))
    pages.push({
      kind: 'api',
      id: domain.id,
      title: domain.title,
      group: 'API',
      what: domain.what,
      why: domain.why,
      when: domain.when,
      where: domain.where,
      how: domain.how,
      howMuch: `${matched.length} endpoints`,
      who: domain.who,
      output: domain.output,
      apis: matched.map((r) => `${r.method} ${r.path}`).join(' · '),
      endpointCount: matched.length,
    })
  }

  pages.push({
    kind: 'api',
    id: 'api-index',
    title: 'מפת API מלאה — כל ה-endpoints',
    group: 'API',
    what: `רשימת ${all.length} HTTP endpoints רשומים ב-weissman-server.`,
    why: 'Due diligence טכני — אין API נסתר.',
    when: 'אינטגרציה, RFP, pen-test scope.',
    where: 'fingerprint_engine/src/http/serve.rs',
    how: 'כל endpoint מאחורי auth/RBAC/billing לפי path.',
    howMuch: `${all.length} routes`,
    who: 'Architect, DevOps, Security',
    output: 'OpenAPI-compatible surface',
    apis: all.map((r) => `${r.method} ${r.path}`).join('\n'),
    endpointCount: all.length,
  })

  return pages
}

function renderDimensionsTable(p) {
  const rows = [
    ['מה', p.what],
    ['למה', p.why],
    ['מתי', p.when],
    ['איפה', p.where],
    ['איך', p.how],
    ['כמה', p.howMuch],
    ['למי', p.who],
    ['מה יוצא', p.output],
  ]
  if (p.apis) rows.push(['API / חיבורים', p.apis])
  if (p.engines) rows.push(['מנועים', p.engines])
  if (p.component) rows.push(['קומponent React', `\`${p.component}\``])
  return rows.map(([k, v]) => `| **${k}** | ${v} |`).join('\n')
}

function renderPageMd(num, p) {
  let md = `\n---\n\n<a id="page-${pad(num)}"></a>\n\n## עמוד ${pad(num)} — ${p.title}\n\n`
  if (p.kind === 'route') {
    md += `> **נתיב:** \`${p.where}\` · **קבוצה:** ${p.group}\n\n`
  } else if (p.kind === 'engine') {
    md += `> **מנוע:** \`${p.id}\` · ${p.groupLabel} · MITRE ${p.mitre || '—'}\n\n`
  } else if (p.kind === 'module' || p.kind === 'api' || p.kind === 'surface') {
    md += `> **סוג:** ${p.kind} · **מזהה:** \`${p.id || '—'}\`\n\n`
  }
  md += renderDimensionsTable(p)
  return md
}

function renderPageHtml(num, p) {
  const rows = [
    ['מה', p.what],
    ['למה', p.why],
    ['מתי', p.when],
    ['איפה', p.where],
    ['איך', p.how],
    ['כמה', p.howMuch],
    ['למי', p.who],
    ['מה יוצא', p.output],
  ]
  if (p.apis) rows.push(['API / חיבורים', p.apis])
  if (p.engines) rows.push(['מנועים', p.engines])
  if (p.component) rows.push(['React', p.component])

  const table = rows
    .map(
      ([k, v]) =>
        `<tr><th>${escapeHtml(k)}</th><td>${escapeHtml(v).replace(/\n/g, '<br/>')}</td></tr>`,
    )
    .join('')

  let meta = ''
  if (p.kind === 'route') meta = `<p class="meta"><code>${escapeHtml(p.where)}</code> · ${escapeHtml(p.group)}</p>`
  if (p.kind === 'engine') meta = `<p class="meta"><code>${escapeHtml(p.id)}</code> · ${escapeHtml(p.groupLabel)} · MITRE ${escapeHtml(p.mitre || '—')}</p>`

  return `<article class="page" id="page-${pad(num)}" data-title="${escapeHtml(p.title)}" data-kind="${p.kind}">
  <header><span class="pagenum">עמוד ${pad(num)}</span><h2>${escapeHtml(p.title)}</h2>${meta}</header>
  <table class="dims">${table}</table>
</article>`
}

function buildHtmlViewer(pages, stats) {
  const articles = pages.map((p, i) => renderPageHtml(i + 1, p)).join('\n')
  const toc = pages
    .map(
      (p, i) =>
        `<a href="#page-${pad(i + 1)}" data-kind="${p.kind}" data-title="${escapeHtml(p.title.toLowerCase())}"><span class="n">${pad(i + 1)}</span>${escapeHtml(p.title)}</a>`,
    )
    .join('\n')

  return `<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Weissman — ספר המוצר</title>
  <style>
    :root {
      --bg: #030712; --panel: #0f172a; --border: rgba(255,255,255,.08);
      --text: #e2e8f0; --muted: #94a3b8; --accent: #38bdf8; --gold: #fbbf24;
    }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: "Segoe UI", "Rubik", system-ui, sans-serif; background: var(--bg); color: var(--text); line-height: 1.65; }
    .layout { display: grid; grid-template-columns: 320px 1fr; min-height: 100vh; }
    aside { background: var(--panel); border-left: 1px solid var(--border); position: sticky; top: 0; height: 100vh; overflow: auto; padding: 1rem; }
    .brand { text-align: center; padding: 1rem .5rem 1.25rem; border-bottom: 1px solid var(--border); margin-bottom: 1rem; }
    .brand h1 { font-size: 1rem; margin: 0; letter-spacing: .12em; color: var(--gold); }
    .brand p { margin: .35rem 0 0; font-size: .78rem; color: var(--muted); }
    #search { width: 100%; padding: .65rem .75rem; border-radius: .5rem; border: 1px solid var(--border); background: #020617; color: var(--text); margin-bottom: .75rem; }
    nav { display: flex; flex-direction: column; gap: 2px; font-size: .78rem; max-height: calc(100vh - 180px); overflow: auto; }
    nav a { color: var(--muted); text-decoration: none; padding: .35rem .5rem; border-radius: .35rem; display: flex; gap: .5rem; align-items: baseline; }
    nav a:hover, nav a.active { background: rgba(56,189,248,.12); color: var(--text); }
    nav .n { color: var(--accent); font-family: ui-monospace, monospace; min-width: 2.2rem; }
    main { padding: 2rem 3rem 4rem; max-width: 920px; }
    .cover { text-align: center; padding: 3rem 1rem 4rem; border-bottom: 1px solid var(--border); margin-bottom: 2rem; }
    .cover h1 { font-size: 2rem; margin: 0 0 .5rem; background: linear-gradient(90deg,#fbbf24,#38bdf8); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .cover .stats { color: var(--muted); font-size: .9rem; }
    article.page { margin-bottom: 3rem; padding-bottom: 2rem; border-bottom: 1px solid var(--border); scroll-margin-top: 1rem; }
    article .pagenum { font-family: ui-monospace, monospace; color: var(--accent); font-size: .75rem; }
    article h2 { margin: .25rem 0 .75rem; font-size: 1.35rem; }
    article .meta { color: var(--muted); font-size: .85rem; margin: 0 0 1rem; }
    table.dims { width: 100%; border-collapse: collapse; font-size: .92rem; }
    table.dims th { text-align: right; width: 7rem; vertical-align: top; color: var(--gold); padding: .5rem .75rem .5rem 0; font-weight: 600; }
    table.dims td { padding: .5rem 0; border-bottom: 1px solid var(--border); }
    @media print {
      aside { display: none; }
      .layout { display: block; }
      main { max-width: none; padding: 1cm; }
      article.page { page-break-inside: avoid; }
    }
    @media (max-width: 900px) {
      .layout { grid-template-columns: 1fr; }
      aside { position: relative; height: auto; max-height: 40vh; }
    }
  </style>
</head>
<body>
  <div class="layout">
    <aside>
      <div class="brand">
        <h1>WEISSMAN CYBERSECURITY</h1>
        <p>ספר המוצר · ${stats.total} עמודים</p>
      </div>
      <input type="search" id="search" placeholder="חיפוש עמוד / מנוע / API…" autocomplete="off"/>
      <nav id="toc">${toc}</nav>
    </aside>
    <main>
      <section class="cover">
        <h1>ספר המוצר — Weissman Cybersecurity</h1>
        <p>כל מה שיש במערכת — לוח · מנוע · API · תשתית</p>
        <p class="stats">${stats.routes} לוחות · ${stats.engines} מנועים · ${stats.apis} API endpoints · ${stats.surfaces} surfaces</p>
      </section>
      ${articles}
    </main>
  </div>
  <script>
    const search = document.getElementById('search');
    const links = [...document.querySelectorAll('#toc a')];
    search?.addEventListener('input', () => {
      const q = search.value.trim().toLowerCase();
      links.forEach(a => {
        const t = a.dataset.title || '';
        a.style.display = !q || t.includes(q) || a.textContent.includes(q) ? '' : 'none';
      });
    });
    const obs = new IntersectionObserver(entries => {
      entries.forEach(e => {
        if (e.isIntersecting) {
          links.forEach(l => l.classList.toggle('active', l.getAttribute('href') === '#' + e.target.id));
        }
      });
    }, { rootMargin: '-20% 0px -70% 0px' });
    document.querySelectorAll('article.page').forEach(el => obs.observe(el));
  </script>
</body>
</html>`
}

function main() {
  const routes = parseRoutes()
  const engineMap = parseRouteEngineMap()
  const engines = parseEngines()

  const routePages = []
  for (const r of routes) {
    if (r === '/') routePages.unshift(buildRoutePage('/', engineMap))
    else routePages.push(buildRoutePage(r, engineMap))
  }

  const introPages = INTRO_PAGES.map((p) => ({ ...p, kind: 'intro' }))
  const modulePages = PLATFORM_MODULES.map((p) => ({ ...p, kind: 'module' }))
  const surfacePages = EXTRA_SURFACES.map((p) => ({ ...p, kind: 'surface' }))
  const apiPages = buildApiDomainPages()

  const enginePages = engines.map((e) => ({
    kind: 'engine',
    id: e.id,
    title: e.label,
    groupLabel: GROUP_HE[e.group] || e.group,
    what: e.description,
    why: `MITRE ${e.mitre || '—'} · probe ${e.agent ? 'Agent (endpoint)' : 'Remote (network/API)'}.`,
    when: e.agent
      ? 'Agent מותקן ו-online.'
      : e.requiresTarget
        ? 'Target/domain ב-scope.'
        : 'Global/config scan.',
    where: `/command-center/engines/${e.id}`,
    how: e.agent
      ? 'Agents → install → Engine Detail → Run.'
      : 'Engine Matrix / Hub → Run → Jobs → Findings.',
    howMuch: `1 quota · ${e.agent ? 'Agent' : 'Remote'} · יעד ${e.requiresTarget ? 'חובה' : 'לא חובה'}`,
    who: e.agent ? 'Endpoint / Red Team' : 'AppSec / SOC',
    output: 'findings + evidence',
    mitre: e.mitre,
    apis: `POST /api/command-center/scan { engine: "${e.id}" }`,
  }))

  const sections = [
    { part: 'א׳', name: 'מבוא', items: introPages },
    { part: 'ב׳', name: 'תשתית', items: modulePages },
    { part: 'ג׳', name: 'Surfaces & Install', items: surfacePages },
    { part: 'ד׳', name: 'Command Center — כל לוח', items: routePages },
    { part: 'ה׳', name: 'API — כל endpoints', items: apiPages },
    { part: 'ו׳', name: '533 מנועים', items: enginePages },
  ]

  const allPages = sections.flatMap((s) => s.items)
  let pageNum = 0
  let tocMd = ''
  let currentPart = ''
  let body = ''

  for (const sec of sections) {
    for (const item of sec.items) {
      pageNum++
      item._page = pageNum
      if (sec.part !== currentPart) {
        currentPart = sec.part
        tocMd += `\n### חלק ${sec.part} — ${sec.name}\n\n| עמוד | נושא | סוג |\n|------|------|-----|\n`
      }
      const kindHe =
        { intro: 'מבוא', module: 'תשתית', surface: 'surface', route: 'לוח', api: 'API', engine: 'מנוע' }[
          item.kind
        ] || item.kind
      tocMd += `| [${pad(pageNum)}](#page-${pad(pageNum)}) | ${item.title} | ${kindHe} |\n`
      body += renderPageMd(pageNum, item)
    }
  }

  const httpApis = parseHttpApiRoutes()
  const stats = {
    total: pageNum,
    routes: routePages.length,
    engines: engines.length,
    apis: httpApis.length,
    surfaces: surfacePages.length,
  }

  const doc = `<div dir="rtl">

<p align="center">
<strong style="font-size:1.5em">WEISSMAN CYBERSECURITY</strong><br/>
<strong style="font-size:1.25em">ספר המוצר — מיפוי מלא של הפלטפורמה</strong><br/>
<em>לוחות · מנועים · APIs · תשתית · surfaces — אפס פערים</em><br/><br/>
גרסה: ${new Date().toISOString().slice(0, 10)} · **${pageNum} עמודים**
</p>

> **להצגה למנכ"ל / מכירות:** פתחו \`docs/sales/viewer/index.html\` בדפדפן — עיצוב CEO, חיפוש, הדפסה ל-PDF.

---

# תוכן עניינים
${tocMd}

---

${body}

---

## נספח כיסוי

| מדד | כמות |
|-----|------|
| עמודים | ${pageNum} |
| לוחות UI | ${routePages.length} |
| מנועים | ${engines.length} |
| HTTP API routes | ${httpApis.length} |
| Surfaces (install, WS, legal) | ${surfacePages.length} |
| Agent-required engines | ${engines.filter((e) => e.agent).length} |

*מחולל: \`node scripts/generate_platform_encyclopedia.mjs\`*

</div>`

  const outDir = join(root, 'docs/sales')
  const viewerDir = join(outDir, 'viewer')
  mkdirSync(viewerDir, { recursive: true })

  writeFileSync(join(outDir, 'WEISSMAN-PLATFORM-ENCYCLOPEDIA.md'), doc, 'utf8')
  writeFileSync(join(viewerDir, 'index.html'), buildHtmlViewer(allPages, stats), 'utf8')
  writeFileSync(join(viewerDir, 'data.json'), JSON.stringify({ stats, pages: allPages.length }, null, 2))

  console.log(`Encyclopedia: ${pageNum} pages`)
  console.log(`  routes=${routePages.length} engines=${engines.length} apis=${httpApis.length} surfaces=${surfacePages.length}`)
  console.log(`  MD: docs/sales/WEISSMAN-PLATFORM-ENCYCLOPEDIA.md`)
  console.log(`  CEO viewer: docs/sales/viewer/index.html`)
}

main()
