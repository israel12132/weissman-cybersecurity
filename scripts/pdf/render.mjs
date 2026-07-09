#!/usr/bin/env node
/* ============================================================================
 * Weissman Cybersecurity — world-class briefing PDF renderer
 * markdown  ->  premium print HTML  ->  PDF (Chromium)
 *
 * Usage: node render.mjs <input.md> <output.pdf> <he|en>
 * ========================================================================== */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import MarkdownIt from 'markdown-it'
import { chromium } from 'playwright-core'
import subsetFont from 'subset-font'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

const [inputPath, outputPath, langArg] = process.argv.slice(2)
if (!inputPath || !outputPath) {
  console.error('usage: render.mjs <input.md> <output.pdf> <he|en>')
  process.exit(1)
}
const lang = (langArg || 'he').toLowerCase()
const rtl = lang === 'he'
const dir = rtl ? 'rtl' : 'ltr'

const STR = {
  he: {
    kicker: 'תקציר מנהלי וטכני · מאומת מול קוד־המקור',
    tocEyebrow: 'ניווט המסמך',
    tocTitle: 'תוכן עניינים',
    sectionsLabel: 'פרקים',
    appendixLabel: 'נספחים',
    classification: 'חסוי · לשימוש פנימי ותחת NDA',
    issuedLabel: 'הופק',
    versionLabel: 'גרסה',
    archTitle: 'ארכיטקטורת המערכת — מבט־על',
    footerConf: 'CONFIDENTIAL',
    headerDoc: 'Weissman Cybersecurity Platform · מסמך חברה ומערכת',
    bandClient: 'משטח הלקוח',
    bandUi: 'מרכז הפיקוד',
    bandApi: 'שרת ה־API',
    bandWorkers: 'ביצוע אסינכרוני',
    bandData: 'נתונים ותשתית נלווית',
    legendTitle: 'זרימות',
  },
  en: {
    kicker: 'Executive & Technical Briefing · Source-Verified',
    tocEyebrow: 'Document Navigation',
    tocTitle: 'Table of Contents',
    sectionsLabel: 'Sections',
    appendixLabel: 'Appendices',
    classification: 'Confidential · Internal & NDA',
    issuedLabel: 'Issued',
    versionLabel: 'Version',
    archTitle: 'System Architecture — Overview',
    footerConf: 'CONFIDENTIAL',
    headerDoc: 'Weissman Cybersecurity Platform · Company & System Briefing',
    bandClient: 'Customer surface',
    bandUi: 'Command Center',
    bandApi: 'API server',
    bandWorkers: 'Async execution',
    bandData: 'Data & sidecars',
    legendTitle: 'Flows',
  },
}[lang] || {}

const ISSUED_DATE = '2026-07-09'

const md = new MarkdownIt({ html: true, linkify: false, typographer: true, breaks: false })

/* ---------------------------------------------------------------------------
 * 1. Read + split source
 * ------------------------------------------------------------------------- */
let raw = fs.readFileSync(inputPath, 'utf8')

// H1 + tagline
const h1Line = (raw.match(/^# (.+)$/m) || [])[1] || 'Weissman Cybersecurity'
const productName = h1Line.split(/\s+[—–-]\s+/)[0].trim()
const titleDescriptor = (h1Line.split(/\s+[—–-]\s+/)[1] || '').trim()
const tagline = (raw.match(/^\*\*(.+)\*\*\s*$/m) || [])[1] || ''

// split at first numbered section "## 1. ..."
const splitMatch = raw.match(/^## (?:1|‏?1)\.\s/m)
const splitIdx = splitMatch ? raw.indexOf(splitMatch[0]) : 0
let bodyMd = splitIdx > 0 ? raw.slice(splitIdx) : raw
const frontMd = splitIdx > 0 ? raw.slice(0, splitIdx) : ''

// front-matter metadata table only (rows: | **label** | value |)
const meta = []
for (const m of frontMd.matchAll(/^\|\s*\*\*(.+?)\*\*\s*\|\s*(.+?)\s*\|\s*$/gm)) {
  meta.push({ k: m[1].trim(), v: m[2].trim() })
}

/* ---------------------------------------------------------------------------
 * 2. Bespoke architecture diagram (replaces the mermaid block)
 * ------------------------------------------------------------------------- */
function node(name, desc) {
  return `<div class="node"><span class="n-name">${name}</span><span class="n-desc">${desc}</span></div>`
}
const D = STR
const archHtml = `
<div class="arch">
  <div class="arch__title">${D.archTitle}</div>
  <div class="arch__flow">
    <div class="band band--client">
      <div class="band__label">${D.bandClient}</div>
      <div class="band__nodes">
        ${node('Web / API / Cloud / OT', rtl ? 'יעדי סריקה מאושרים' : 'authorized scan targets')}
        ${node('weissman-agent', rtl ? 'קצה · Linux / macOS / Windows' : 'endpoint · Linux / macOS / Windows')}
      </div>
    </div>
    <div class="band band--ui">
      <div class="band__label">${D.bandUi}</div>
      <div class="band__nodes">
        ${node('Cockpit (React/Vite SPA)', rtl ? 'רצועת KPI חיה · SSE + WebSocket war-room' : 'live KPI strip · SSE + WebSocket war-room')}
      </div>
    </div>
    <div class="band band--api">
      <div class="band__label">${D.bandApi} · weissman-server (Axum :8000)</div>
      <div class="band__nodes">
        ${node('REST + WS', rtl ? '~130 נקודות־קצה · 6 WebSockets' : '~130 endpoints · 6 WebSockets')}
        ${node('AuthZ', rtl ? 'JWT · MFA · SSO · RBAC 6 דרגות' : 'JWT · MFA · SSO · 6-tier RBAC')}
        ${node('Orchestrator', rtl ? 'מחזור סריקה לכל־דייר' : 'per-tenant scan cycle')}
        ${node('Intel workers', rtl ? 'KEV/EPSS · SOAR · self-scan' : 'KEV/EPSS · SOAR · self-scan')}
      </div>
    </div>
    <div class="band band--workers">
      <div class="band__label">${D.bandWorkers}</div>
      <div class="band__nodes">
        ${node('weissman-worker', rtl ? 'תור SKIP LOCKED · timeouts לכל־סוג' : 'SKIP LOCKED queue · per-kind timeouts')}
        ${node('Engine fleet', rtl ? '563 מזהים · 303 real_probe · 212 alias · 48 agent' : '563 IDs · 303 real_probe · 212 alias · 48 agent')}
        ${node('weissman-oast-server', rtl ? 'לכידת קריאות DNS + HTTP' : 'DNS + HTTP callback capture')}
      </div>
    </div>
    <div class="band band--data">
      <div class="band__label">${D.bandData}</div>
      <div class="band__nodes">
        ${node('PostgreSQL 16 + pgvector', rtl ? '~88 טבלאות · RLS · 74+ מיגרציות' : '~88 tables · RLS · 74+ migrations')}
        ${node('Redis', rtl ? 'הגבלת־קצב · נוכחות · pub/sub' : 'rate limits · presence · pub/sub')}
        ${node('OpenAI-compatible LLMs', rtl ? 'vLLM / Ollama / OpenAI' : 'vLLM / Ollama / OpenAI')}
      </div>
    </div>
  </div>
  <div class="arch__legend">
    <span class="legchip"><span class="lc">SSE + WS</span> ${rtl ? 'Cockpit ⇄ API' : 'Cockpit ⇄ API'}</span>
    <span class="legchip"><span class="lc">WSS + JWT</span> ${rtl ? 'Agent ⇄ API' : 'Agent ⇄ API'}</span>
    <span class="legchip"><span class="lc">probes</span> ${rtl ? 'Engines → יעדים' : 'Engines → targets'}</span>
    <span class="legchip"><span class="lc">OAST</span> ${rtl ? 'Engines → קריאות־חזרה' : 'Engines → callbacks'}</span>
  </div>
</div>
`

// replace the fenced mermaid block with the bespoke diagram (as raw HTML block)
bodyMd = bodyMd.replace(/```mermaid[\s\S]*?```/m, `\n\n${archHtml}\n\n`)

/* ---------------------------------------------------------------------------
 * 3. Markdown -> HTML + heading processing + TOC collection
 * ------------------------------------------------------------------------- */
let bodyHtml = md.render(bodyMd)

const toc = []
function stripTags(s) { return s.replace(/<[^>]+>/g, '').trim() }

let hIndex = 0
bodyHtml = bodyHtml.replace(/<h2>([\s\S]*?)<\/h2>/g, (full, inner) => {
  hIndex += 1
  const text = stripTags(inner)
  const isAppendix = /^(נספח|Appendix)\b/i.test(text) || text.startsWith('נספח')
  let id, chip, label, tocNum
  if (isAppendix) {
    const mm = text.match(/^(?:נספח|Appendix)\s+([^\s—–-]+)/i)
    const letter = mm ? mm[1].replace(/['׳"]/g, '') : String.fromCharCode(64 + hIndex)
    id = `app-${hIndex}`
    chip = letter
    label = text
    tocNum = letter
  } else {
    const mm = text.match(/^(\d+)\.\s*([\s\S]+)$/)
    const num = mm ? mm[1] : String(hIndex)
    label = mm ? mm[2] : text
    id = `sec-${num}`
    chip = num
    tocNum = num
  }
  toc.push({ id, num: tocNum, label, appendix: isAppendix })
  const cls = isAppendix ? 'appendix pbreak' : ''
  return `<h2 id="${id}" class="${cls}"><span class="secnum">${chip}</span>${escapeHtml(label)}</h2>`
})

function escapeHtml(s) {
  return s.replace(/&(?!#?\w+;)/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

/* ---------------------------------------------------------------------------
 * 4. Cover + TOC HTML
 * ------------------------------------------------------------------------- */
const coverTitle = rtl ? (titleDescriptor || 'מסמך חברה ומערכת')
                       : (titleDescriptor || 'Company & System Briefing')

// metadata cells (render inline markdown in values)
const metaCells = meta.map(({ k, v }) => {
  const long = stripTags(md.renderInline(v)).length > 40
  return `<div class="metacell${long ? ' metacell--wide' : ''}"><span class="k">${escapeHtml(k)}</span><span class="v">${md.renderInline(v)}</span></div>`
}).join('\n')

const shieldSvg = `
<svg viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <defs>
    <linearGradient id="sg" x1="10" y1="4" x2="54" y2="60" gradientUnits="userSpaceOnUse">
      <stop stop-color="#28D2DE"/><stop offset="1" stop-color="#0E7C86"/>
    </linearGradient>
  </defs>
  <path d="M32 4l22 8v16c0 14.4-9.4 27.3-22 32C19.4 55.3 10 42.4 10 28V12L32 4z"
        fill="url(#sg)" opacity="0.16"/>
  <path d="M32 4l22 8v16c0 14.4-9.4 27.3-22 32C19.4 55.3 10 42.4 10 28V12L32 4z"
        stroke="url(#sg)" stroke-width="2.2"/>
  <path d="M22 31l7 7 14-15" stroke="#7FEAF1" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/>
</svg>`

const coverHtml = `
<section class="cover">
  <div class="cover__inner">
    <div class="brandrow">
      <div class="brandmark">${shieldSvg}</div>
      <div class="brandwords">
        <span class="b1">WEISSMAN</span>
        <span class="b2">CYBERSECURITY</span>
      </div>
    </div>
    <div class="cover__spacer"></div>
    <div class="cover__kicker">${escapeHtml(STR.kicker)}</div>
    <h1 class="cover__title">${escapeHtml(coverTitle)}</h1>
    <div class="cover__rule"></div>
    <p class="cover__subtitle">${escapeHtml(tagline)}</p>
    <div class="cover__meta">${metaCells}</div>
    <div class="cover__foot">
      <span class="classbadge"><span class="dot"></span>${escapeHtml(STR.classification)}</span>
      <span class="issued">${STR.issuedLabel}: ${ISSUED_DATE}<br>${productName}</span>
    </div>
  </div>
</section>`

// TOC — sections split across two balanced columns, appendices below
const tocSections = toc.filter((t) => !t.appendix)
const tocAppendix = toc.filter((t) => t.appendix)
function tocItems(items) {
  return items.map((t) =>
    `<a class="toc__item${t.appendix ? ' toc__item--appendix' : ''}" href="#${t.id}">
      <span class="toc__num">${escapeHtml(String(t.num))}</span>
      <span class="toc__label">${escapeHtml(t.label)}</span>
    </a>`).join('\n')
}
const half = Math.ceil(tocSections.length / 2)
const secCol1 = tocSections.slice(0, half)
const secCol2 = tocSections.slice(half)
const tocHtml = `
<section class="toc">
  <div class="toc__head">
    <div class="toc__eyebrow">${escapeHtml(STR.tocEyebrow)}</div>
    <h1 class="toc__title">${escapeHtml(STR.tocTitle)}</h1>
    <div class="toc__rule"></div>
  </div>
  <div class="toc__group-label">${escapeHtml(STR.sectionsLabel)}</div>
  <div class="toc__grid">
    <div class="toc__section">${tocItems(secCol1)}</div>
    <div class="toc__section">${tocItems(secCol2)}</div>
  </div>
  <div class="toc__group-label toc__group-label--appendix">${escapeHtml(STR.appendixLabel)}</div>
  <div class="toc__grid">
    <div class="toc__section">${tocItems(tocAppendix.slice(0, 2))}</div>
    <div class="toc__section">${tocItems(tocAppendix.slice(2))}</div>
  </div>
</section>`

/* ---------------------------------------------------------------------------
 * 5. Fonts (embedded) + assemble document
 * ------------------------------------------------------------------------- */
// Chromium does not subset *variable* fonts when printing — it embeds a full
// copy per rendered weight, bloating the PDF. So we pin each used weight to a
// static instance and glyph-subset it to the characters actually in the doc.
const usedText = coverHtml + tocHtml + bodyHtml +
  ' 0123456789…—–‑·•⇄→←↔״׳“”‘’()[]{}/\\<>%+=:;.,\'"`~@#&*|_^°'
const FONTS = [
  { family: 'Frank Ruhl Libre', file: 'FrankRuhlLibre.ttf', weights: [800, 900] },
  { family: 'Assistant',        file: 'Assistant.ttf',       weights: [400, 500, 600, 700] },
  { family: 'Heebo',            file: 'Heebo.ttf',            weights: [500, 600, 700, 800] },
  { family: 'JetBrains Mono',   file: 'JetBrainsMono.ttf',    weights: [400, 700] },
]
async function buildFontFaces() {
  const faces = []
  for (const f of FONTS) {
    const full = fs.readFileSync(path.join(__dirname, 'fonts', f.file))
    for (const w of f.weights) {
      let buf = full
      try {
        buf = await subsetFont(full, usedText, { targetFormat: 'truetype', variationAxes: { wght: w } })
      } catch (e) {
        console.warn(`  font instance ${f.family}@${w} fell back to full: ${e.message}`)
      }
      const b64 = Buffer.from(buf).toString('base64')
      faces.push(`@font-face{font-family:'${f.family}';font-style:normal;font-weight:${w};font-display:swap;src:url(data:font/ttf;base64,${b64}) format('truetype');}`)
    }
  }
  return faces.join('\n')
}
const fontsCss = await buildFontFaces()

const themeCss = fs.readFileSync(path.join(__dirname, 'theme.css'), 'utf8')

function fullDoc(inner) {
  return `<!doctype html>
<html lang="${lang}" dir="${dir}">
<head>
<meta charset="utf-8">
<style>${fontsCss}</style>
<style>${themeCss}</style>
</head>
<body>
${inner}
</body>
</html>`
}

const coverDoc = fullDoc(coverHtml)
const bodyDoc = fullDoc(`${tocHtml}\n<main class="doc">\n${bodyHtml}\n</main>`)

// optional combined HTML artifact for inspection (set PDF_DEBUG=1)
if (process.env.PDF_DEBUG) {
  const htmlOut = outputPath.replace(/\.pdf$/i, '.html')
  fs.writeFileSync(htmlOut, fullDoc(`${coverHtml}\n${tocHtml}\n<main class="doc">\n${bodyHtml}\n</main>`))
  console.log(`HTML written: ${htmlOut}`)
}
console.log(`Parsed: sections=${tocSections.length} appendices=${tocAppendix.length}`)

/* ---------------------------------------------------------------------------
 * 6. Print to PDF via Chromium (cover has no running header/footer)
 * ------------------------------------------------------------------------- */
const headerTemplate = `
<div style="width:100%;font-family:Helvetica,Arial,sans-serif;font-size:6.5pt;color:#9DB0BC;
     padding:0 18mm;box-sizing:border-box;display:flex;align-items:center;justify-content:space-between;">
  <span style="letter-spacing:.06em;">WEISSMAN CYBERSECURITY</span>
  <span style="color:#B9C7D1;">Company &amp; System Briefing</span>
</div>`

const footerTemplate = `
<div style="width:100%;font-family:Helvetica,Arial,sans-serif;font-size:6.8pt;color:#8496A2;
     padding:0 18mm;box-sizing:border-box;display:flex;align-items:center;justify-content:space-between;
     border-top:0.5px solid #E4EAF1;padding-top:2mm;">
  <span style="letter-spacing:.05em;">${productName.toUpperCase()}</span>
  <span style="color:#C77A12;font-weight:600;letter-spacing:.08em;">${STR.footerConf}</span>
  <span style="font-variant-numeric:tabular-nums;"><span class="pageNumber"></span>&nbsp;/&nbsp;<span class="totalPages"></span></span>
</div>`

const execPath = path.join(process.env.PLAYWRIGHT_BROWSERS_PATH || '/opt/pw-browsers', 'chromium')
const browser = await chromium.launch({ executablePath: execPath, args: ['--no-sandbox', '--font-render-hinting=none'] })

async function renderPdf(htmlStr, opts) {
  const page = await browser.newPage()
  await page.emulateMedia({ media: 'print' })
  await page.setContent(htmlStr, { waitUntil: 'networkidle' })
  await page.evaluate(() => document.fonts.ready)
  const buf = await page.pdf({ format: 'A4', printBackground: true, preferCSSPageSize: true, ...opts })
  await page.close()
  return buf
}

const coverBuf = await renderPdf(coverDoc, { displayHeaderFooter: false })
const bodyBuf = await renderPdf(bodyDoc, { displayHeaderFooter: true, headerTemplate, footerTemplate })
if (process.env.PDF_DEBUG) console.log(`  cover=${(coverBuf.length/1024).toFixed(0)}KB body=${(bodyBuf.length/1024).toFixed(0)}KB`)
await browser.close()

// merge: use the body PDF as the base (its 28 pages already share one set of
// embedded fonts) and graft only the single cover page to the front. This
// avoids re-grafting every body page, which would duplicate the fonts per page.
const mupdf = await import('mupdf')
const dst = mupdf.PDFDocument.openDocument(new Uint8Array(bodyBuf), 'application/pdf')
const cover = mupdf.PDFDocument.openDocument(new Uint8Array(coverBuf), 'application/pdf')
dst.graftPage(0, cover, 0)
const merged = dst.saveToBuffer('compress')
fs.writeFileSync(outputPath, Buffer.from(merged.asUint8Array()))

const kb = (fs.statSync(outputPath).size / 1024).toFixed(0)
console.log(`PDF written: ${outputPath} (${kb} KB)`)
