// Maintenance page template — one function renders every locale/variant.
// Copy lives in ./strings.mjs; behaviour in ./maintenance.js; the mark in ./logo.svg.
// Design contract (ids, tokens, layout, BIDI, a11y): deploy/maintenance/README.md.
import { STRINGS, EMAIL } from './strings.mjs';

export const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

// ./logo.svg minus its outer <svg> wrapper: the gradient id is "wm-g" in the inline mark.
export function markInner(svgSource) {
  const s = String(svgSource).trim();
  const open = s.indexOf('>');
  const close = s.lastIndexOf('</svg>');
  if (!s.startsWith('<svg') || open < 0 || close < 0) { throw new Error('logo.svg: expected a single <svg>…</svg>'); }
  return s.slice(open + 1, close).trim();
}
// Inline mark (decorative; the wordmark carries the name).
const markSvg = (mark, size) => `<svg class="mark" width="${size}" height="${size}" viewBox="0 0 64 64" fill="none" aria-hidden="true" focusable="false">${mark}</svg>`;
// Same mark as a data: favicon so the browser never requests /favicon.ico from a dead origin.
const favicon = (mark) => 'data:image/svg+xml,' + encodeURIComponent(
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" fill="none">${mark.replace(/wm-g/g, 'g')}</svg>`
);
// Locale pill (public pages only): set in the OTHER locale's font.
const langPill = (S) => `  <a class="lang" href="${S.switchHref}" lang="${S.switchLang}" hreflang="${S.switchLang}" dir="${S.switchDir}" title="${esc(S.switchTitle)}">${S.switchLabel}</a>\n`;

const css = (fonts) => `
:root{--bg-deep:#07090c;--bg-charcoal:#10141b;--bg-elevated:#161b24;--bg-glow:rgba(34,211,238,.08);--text:#f4efe6;--text-muted:#b7b1a6;--text-dim:#7d776c;--accent:#22d3ee;--accent-dim:rgba(34,211,238,.16);--accent-deep:#0ea5e9;--risk:#e8b86d;--ops:#3ee0b2;--danger:#f07167;--line:rgba(244,239,230,.1);--line-strong:rgba(244,239,230,.18);--radius:14px;--radius-sm:10px;--shadow:0 18px 50px rgba(0,0,0,.35);--ease:cubic-bezier(.22,1,.36,1);--duration-swift:180ms;--duration:280ms;--duration-slow:480ms;--font-sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;--font-brand:"Orbitron",var(--font-sans);--font-mono:ui-monospace,"SF Mono",Menlo,Consolas,"Liberation Mono","Courier New",monospace;--font-he:"Heebo",var(--font-sans);--dot:var(--accent);--dot-ring:var(--accent-dim)}
/* Command Center variant: same design family, palette leans to the app's slate. */
html[data-variant=command-center]{--bg-deep:#020617;--bg-charcoal:#0f172a;--bg-elevated:#1e293b;--line:rgba(226,232,240,.1);--line-strong:rgba(226,232,240,.18);--text:#e2e8f0;--text-muted:#94a3b8;--text-dim:#64748b}
@media (prefers-reduced-motion:reduce){:root{--duration-swift:1ms;--duration:1ms;--duration-slow:1ms}}
@font-face{font-family:"Orbitron";font-style:normal;font-weight:700;font-display:swap;src:url(data:font/woff2;base64,${fonts.orbitron}) format("woff2");unicode-range:U+0000-00FF,U+2000-206F}
@font-face{font-family:"Heebo";font-style:normal;font-weight:500;font-display:swap;src:url(data:font/woff2;base64,${fonts.heebo}) format("woff2");unicode-range:U+0590-05FF,U+200C-2010,U+20AA,U+25CC,U+FB1D-FB4F}
*,*::before,*::after{box-sizing:border-box}
html{background:var(--bg-deep);color-scheme:dark;-webkit-text-size-adjust:100%;text-size-adjust:100%}
body{margin:0;min-height:100vh;min-height:100dvh;display:flex;flex-direction:column;color:var(--text);background:var(--bg-deep) radial-gradient(60% 38% at 50% -6%,var(--bg-glow),transparent 70%) no-repeat;font:400 1rem/1.6 var(--font-sans);-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}
html[dir=rtl] body{font-family:var(--font-he);font-weight:500}
[hidden]{display:none!important}
a{color:inherit;text-decoration:none}
::selection{background:var(--accent-dim);color:var(--text)}
:focus-visible{outline:2px solid var(--accent);outline-offset:3px;border-radius:4px}
.skip{position:absolute;inset-inline-start:1rem;top:-3rem;padding:.5rem .75rem;background:var(--bg-elevated);border:1px solid var(--line-strong);border-radius:var(--radius-sm);z-index:10}
.skip:focus-visible{top:1rem}
.page{flex:1;display:flex;flex-direction:column;width:100%;max-width:42rem;margin:0 auto;padding:1.25rem clamp(1rem,4vw,2rem) 1.5rem}
.top{display:flex;align-items:center;justify-content:space-between;gap:1rem;padding-block:.5rem}
.brand{display:inline-flex;align-items:center;gap:.75rem;padding:.25rem;margin:-.25rem}
.mark{display:block;flex:none;filter:drop-shadow(0 0 10px rgba(34,211,238,.32))}
.brand-text{display:flex;flex-direction:column;gap:.3rem}
.wordmark{font:700 .82rem/1 var(--font-brand);letter-spacing:.24em;color:var(--text);padding-inline-start:.02em}
.wordsub{font:500 .6875rem/1 var(--font-mono);letter-spacing:.28em;color:var(--text-dim);text-transform:uppercase}
.lang{font-size:.85rem;color:var(--text-muted);padding:.35rem .7rem;border:1px solid var(--line);border-radius:999px;transition:color var(--duration-swift) var(--ease),border-color var(--duration-swift) var(--ease)}
.lang:hover{color:var(--text);border-color:var(--line-strong)}
html[dir=rtl] .lang{font-family:var(--font-sans);font-weight:400}
html[dir=ltr] .lang{font-family:var(--font-he);font-weight:500}
main{flex:1;display:flex;flex-direction:column;justify-content:center;padding-block:clamp(2rem,7vh,4.5rem) clamp(2rem,6vh,3.5rem)}
.eyebrow{display:flex;align-items:center;gap:.6rem;margin:0 0 1rem;font:500 .74rem/1 var(--font-mono);letter-spacing:.16em;text-transform:uppercase;color:var(--text-muted)}
html[dir=rtl] .eyebrow{font:500 .9rem/1 var(--font-he);letter-spacing:0;text-transform:none}
.eyebrow .dot{width:8px;height:8px;border-radius:50%;background:var(--dot);box-shadow:0 0 0 3px var(--dot-ring);flex:none;transition:background var(--duration) var(--ease)}
.eb-planned{display:none}
html[data-mode=planned] .eb-default{display:none}
html[data-mode=planned] .eb-planned{display:inline}
html[data-overdue] {--dot:var(--risk);--dot-ring:rgba(232,184,109,.2)}
h1{margin:0;font-size:clamp(1.75rem,1.2rem + 2.4vw,2.5rem);line-height:1.15;font-weight:600;letter-spacing:-.02em;text-wrap:balance}
html[dir=rtl] h1{font-weight:500;letter-spacing:0;line-height:1.25}
.lede{margin:1rem 0 0;max-width:36rem;font-size:1.05rem;line-height:1.65;color:var(--text-muted);text-wrap:pretty}
.card{margin-top:2rem;background:var(--bg-charcoal);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);overflow:hidden}
.card-head{display:flex;align-items:center;justify-content:space-between;gap:1rem;padding:.8rem 1.25rem;border-bottom:1px solid var(--line)}
.card-head h2{margin:0;font-size:.9rem;font-weight:600;letter-spacing:.01em}
html[dir=rtl] .card-head h2{font-weight:500}
.live{display:flex;align-items:flex-start;gap:.85rem;padding:1.15rem 1.25rem .35rem}
.live p{margin:0;font-size:1rem;line-height:1.5}
.pulse{position:relative;flex:none;width:10px;height:10px;margin-top:.45rem;border-radius:50%;background:var(--dot);transition:background var(--duration) var(--ease)}
.pulse::after{content:"";position:absolute;inset:-5px;border-radius:50%;border:1.5px solid var(--dot);opacity:0;animation:ring 2.6s var(--ease) infinite}
@keyframes ring{0%{transform:scale(.45);opacity:.9}100%{transform:scale(1.5);opacity:0}}
.live[data-state=checking] .pulse::after{animation-duration:1.1s}
.live[data-state=up] .pulse{background:var(--ops)}
.live[data-state=up] .pulse::after{animation:none;opacity:0}
.live[data-state=offline] .pulse{background:var(--text-dim)}
.live[data-state=offline] .pulse::after{animation:none;opacity:0}
@media (prefers-reduced-motion:reduce){.pulse::after{animation:none!important;transform:none;opacity:.35}}
.meta{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1rem 1.25rem;margin:0;padding:1rem 1.25rem 1.25rem}
.meta div{min-width:0}
.meta dt{margin:0 0 .3rem;font:500 .7rem/1 var(--font-mono);letter-spacing:.14em;text-transform:uppercase;color:var(--text-muted)}
html[dir=rtl] .meta dt{font:500 .82rem/1 var(--font-he);letter-spacing:0;text-transform:none}
.meta dd{margin:0;font:400 .95rem/1.4 var(--font-mono);font-variant-numeric:tabular-nums;color:var(--text);overflow-wrap:anywhere}
html[dir=rtl] .meta dd{font-family:var(--font-he);font-weight:500}
.planned{padding:1rem 1.25rem 1.15rem;border-top:1px solid var(--accent-dim);background:rgba(34,211,238,.055)}
.planned h3{margin:0 0 .75rem;font:500 .7rem/1 var(--font-mono);letter-spacing:.14em;text-transform:uppercase;color:var(--accent)}
html[dir=rtl] .planned h3{font:500 .85rem/1 var(--font-he);letter-spacing:0;text-transform:none}
.planned dl{margin:0;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.9rem 1.25rem}
.planned dt{margin:0 0 .25rem;font-size:.78rem;color:var(--text-muted)}
.planned dd{margin:0;font-size:.95rem;overflow-wrap:anywhere}
.planned time{font-variant-numeric:tabular-nums}
.actions{display:flex;align-items:center;flex-wrap:wrap;gap:.75rem 1rem;margin:0;padding:1rem 1.25rem;border-top:1px solid var(--line);background:rgba(244,239,230,.02)}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:.5rem;min-height:2.65rem;appearance:none;font:600 .9rem/1 var(--font-sans);color:var(--bg-deep);background:var(--accent);border:1px solid transparent;border-radius:var(--radius-sm);padding:.6rem 1.15rem;cursor:pointer;transition:background var(--duration-swift) var(--ease),border-color var(--duration-swift) var(--ease),color var(--duration-swift) var(--ease),transform var(--duration-swift) var(--ease)}
html[dir=rtl] .btn{font-family:var(--font-he);font-weight:500}
.btn:hover{background:#5fe1f2}
.btn:active{transform:translateY(1px)}
.btn[disabled],.btn[aria-busy=true]{opacity:.65;cursor:progress}
.btn:focus-visible{outline-offset:3px}
.btn-ghost{color:var(--text);background:transparent;border-color:var(--line-strong)}
.btn-ghost:hover{background:transparent;border-color:var(--accent);color:var(--accent)}
.btn-ghost svg{flex:none;opacity:.7}
html[dir=rtl] .btn-ghost svg{transform:scaleX(-1)}
.hint{font-size:.82rem;color:var(--text-muted)}
.assure{display:flex;align-items:flex-start;gap:.7rem;margin:1.5rem 0 0;padding:0 .25rem;color:var(--text-muted);font-size:.95rem;line-height:1.55}
.assure svg{flex:none;margin-top:.22rem;color:var(--ops)}
.details{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));margin:2.25rem 0 0;border-top:1px solid var(--line);border-bottom:1px solid var(--line)}
.details>div{min-width:0;padding:1.05rem 1.35rem;border-inline-start:1px solid var(--line)}
.details>div:first-child,.details>div.lead{border-inline-start:0;padding-inline-start:0}
.details>div:nth-child(2){border-inline-start:0;padding-inline-start:0}
.details>div.lead{grid-column:1/-1;border-bottom:1px solid var(--line)}
.details dt{margin:0 0 .35rem;font:500 .7rem/1.3 var(--font-mono);letter-spacing:.14em;text-transform:uppercase;color:var(--text-muted)}
html[dir=rtl] .details dt{font:500 .85rem/1.3 var(--font-he);letter-spacing:0;text-transform:none}
.details dd{margin:0;font-size:.95rem;color:var(--text);overflow-wrap:anywhere}
.details .lead dt{font:500 1rem/1.4 var(--font-sans);letter-spacing:0;text-transform:none;color:var(--text);margin-bottom:.4rem}
html[dir=rtl] .details .lead dt{font-family:var(--font-he)}
.details .lead dd{font-size:1rem}
.details a,.footer a{color:var(--text);border-bottom:1px solid var(--line-strong);padding-bottom:1px;transition:color var(--duration-swift) var(--ease),border-color var(--duration-swift) var(--ease)}
.details a:hover,.footer a:hover{color:var(--accent);border-color:var(--accent)}
.details .lead a{color:var(--accent);border-color:rgba(34,211,238,.35)}
.details .lead a:hover{color:#5fe1f2}
.mono{font-family:var(--font-mono);font-size:.92em}
.footer{display:flex;align-items:baseline;justify-content:space-between;flex-wrap:wrap;gap:.5rem 1.25rem;padding-top:1.25rem;border-top:1px solid var(--line);font-size:.78rem;color:var(--text-muted)}
.footer p{margin:0}
.footer .city{white-space:nowrap}
.footer .tech{font-family:var(--font-mono);font-size:.72rem;letter-spacing:.02em;color:var(--text-dim);white-space:nowrap}
@media (max-width:600px){.meta,.planned dl,.details{grid-template-columns:1fr}.meta{gap:.9rem}.details>div{border-inline-start:0;padding-inline:0;padding-block:.95rem;border-top:1px solid var(--line)}.details>div:first-child{border-top:0}.details>div.lead{border-bottom:0}.actions{align-items:stretch;flex-direction:column}.actions .btn{width:100%}.hint{font-size:.8rem}.footer{flex-direction:column;align-items:flex-start;gap:.4rem}}
@media (max-width:400px){.footer .sep{display:none}.footer .city{display:block}}
@media (max-width:360px){.details .lead dd{font-size:.92rem}.lang{padding:.3rem .55rem;font-size:.8rem}.wordmark{font-size:.74rem}.wordsub{font-size:.625rem}}
@media (min-width:900px){.page{max-width:44rem}}
@media print{body{background:#fff;color:#000}.card{box-shadow:none}}
`.trim();

export function page({ locale = 'en', variant = 'public', assetBase = '/maintenance/', fonts, mark }) {
  if (!fonts || !mark) { throw new Error('page(): fonts and mark are required'); }
  const cc = variant === 'command-center';
  const base = STRINGS[locale] || STRINGS.en;
  const S = cc ? { ...base, ...base.cc } : base;
  const l10nAttrs = Object.entries(S.l10n).map(([k, v]) => ` data-l10n-${k}="${esc(v)}"`).join('');
  const ARROW = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true" focusable="false"><path d="M5 12h14M13 6l6 6-6 6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
  return `<!DOCTYPE html>
<html lang="${S.lang}" dir="${S.dir}" data-locale="${S.lang}" data-variant="${variant}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="${cc ? '#020617' : '#07090c'}">
<meta name="color-scheme" content="dark">
<meta name="robots" content="noindex,nofollow">
<meta name="referrer" content="no-referrer">
<meta name="description" content="${esc(S.description)}">
<title>${esc(S.title)}</title>
<link rel="icon" type="image/svg+xml" href="${favicon(mark)}">
<noscript><meta http-equiv="refresh" content="30"></noscript>
<style>
${css(fonts)}
</style>
<script defer src="${assetBase}maintenance.js"></script>
</head>
<body>
<a class="skip" href="#main">${esc(S.skip)}</a>
<div class="page">
<header class="top">
  <a class="brand" href="${S.brandHref}" aria-label="${esc(S.brandLabel)}" dir="ltr">
    ${markSvg(mark, 30)}
    <span class="brand-text" aria-hidden="true"><span class="wordmark">WEISSMAN</span><span class="wordsub">Cybersecurity</span></span>
  </a>
${cc ? '' : langPill(S)}</header>

<main id="main">
  <p class="eyebrow"><span class="dot" aria-hidden="true"></span><span class="eb-default">${esc(S.eyebrow)}</span><span class="eb-planned">${esc(S.eyebrowPlanned)}</span></p>
  <h1 id="maint-headline">${esc(S.h1)}</h1>
  <p class="lede">${esc(S.lede)}</p>

  <section class="card" aria-labelledby="maint-card-title">
    <div class="card-head">
      <h2 id="maint-card-title">${esc(S.cardTitle)}</h2>
    </div>
    <div class="live" id="maint-live" data-state="pending"${l10nAttrs}>
      <span class="pulse" aria-hidden="true"></span>
      <p id="maint-state" role="status" aria-live="polite">${esc(S.stateStatic)}</p>
    </div>
    <dl class="meta">
      <div><dt>${esc(S.dtLast)}</dt><dd id="maint-last-checked">${esc(S.ddLast)}</dd></div>
      <div><dt>${esc(S.dtNext)}</dt><dd id="maint-countdown">${esc(S.ddNext)}</dd></div>
    </dl>
    <div class="planned" id="maint-planned" hidden>
      <h3>${esc(S.plannedTitle)}</h3>
      <dl>
        <div id="maint-reason-row" hidden><dt>${esc(S.plannedReason)}</dt><dd id="maint-reason"></dd></div>
        <div id="maint-until-row" hidden><dt>${esc(S.plannedUntil)}</dt><dd><time id="maint-until"></time></dd></div>
      </dl>
    </div>
    <form class="actions" id="maint-retry-form" method="get" action="">
      <button class="btn" id="maint-retry" type="submit" aria-describedby="maint-retry-hint">${esc(S.retry)}</button>
      <noscript><a class="btn" href="">${esc(S.retry)}</a><style>#maint-retry{display:none}</style></noscript>
      <a class="btn btn-ghost" href="/status">${esc(S.statusBtn)}${ARROW}</a>
      <span class="hint" id="maint-retry-hint">${esc(S.retryHint)}</span>
    </form>
  </section>

  <p class="assure"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true" focusable="false"><path d="M12 3 4.5 6v5.2c0 4.4 3.1 8 7.5 9.8 4.4-1.8 7.5-5.4 7.5-9.8V6L12 3Z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="m8.8 12.2 2.2 2.2 4.3-4.6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg><span>${esc(S.assure)}</span></p>

  <dl class="details">
    <div class="lead"><dt>${esc(S.contactLead)}</dt><dd><a class="mono" href="mailto:${EMAIL}" dir="ltr" lang="en">${EMAIL}</a></dd></div>
    <div><dt>${esc(S.ctStatus)}</dt><dd><a class="mono" href="/status" dir="ltr" lang="en">${esc(S.ctStatusText)}</a></dd></div>
    <div><dt>${esc(S.ctWindow)}</dt><dd>${S.ctWindowValue}</dd></div>
  </dl>
</main>

<footer class="footer">
  <p class="copy">${S.footerCopy}</p>
  <p class="tech" dir="ltr" lang="en">${esc(S.footerTech)}</p>
</footer>
</div>
</body>
</html>
`;
}
