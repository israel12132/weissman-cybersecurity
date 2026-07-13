# Briefing PDF builder

Renders the Weissman Cybersecurity **Company & System Briefing** markdown into
print-quality, board-ready PDFs — one Hebrew (RTL), one English (LTR).

The generated deliverables live at the repository root, next to their sources:

| Source markdown | Output PDF |
|---|---|
| `Weissman_Cybersecurity_מסמך_טכני_מנהלי_עברית.md` | `Weissman_Cybersecurity_מסמך_טכני_מנהלי_עברית.pdf` |
| `Weissman_Cybersecurity_Executive_Technical_Briefing.md` | `Weissman_Cybersecurity_Executive_Technical_Briefing.pdf` |

## Build

```bash
cd scripts/pdf
npm install          # markdown-it, playwright-core, subset-font, mupdf
npm run build        # builds both languages -> repo root
# or individually:
npm run build:he
npm run build:en
```

Chromium is located via `PLAYWRIGHT_BROWSERS_PATH` (falls back to
`/opt/pw-browsers`). No browser download is performed.

Set `PDF_DEBUG=1` to also emit the intermediate HTML next to the PDF and print
cover/body sizes.

## What it does

`render.mjs` turns the markdown into a premium print document:

- **Cover** built from the front-matter metadata table (product, category,
  version, footprint, license …), with brand emblem, classification band and
  issue date.
- **Document Control + Legal & Confidentiality Notice** front-matter pages
  (document ID, version, classification, owner, revision history; NDA,
  copyright, no-warranty, forward-looking, and regulatory-alignment notices),
  generated bilingually.
- **PDF bookmarks** (front matter + every section/appendix, panel open by
  default) and **document metadata** (title/author/subject/keywords/language).
- **KPI "by the numbers"** band on the executive summary.
- **Clickable table of contents** — sections split across two balanced columns,
  appendices below; every entry is an internal PDF link.
- **Bespoke architecture diagram** replacing the Mermaid block, hand-laid so the
  Hebrew (RTL) and English (LTR) versions both read correctly.
- **Design system** (`theme.css`) — a navy + teal palette, serif section
  headings with numbered chips, styled tables, callouts, dark code cards, and
  engine-ID / API monospace chips.
- **Running header/footer** with page numbers and a confidentiality mark
  (suppressed on the cover by rendering the cover separately and grafting it to
  the front with `mupdf`).

### Typography

Four embedded variable fonts (`fonts/*.ttf`, OFL): Frank Ruhl Libre (display),
Assistant (body), Heebo (labels), JetBrains Mono (code). Because Chromium does
not subset *variable* fonts when printing, each used weight is pinned to a
static instance and glyph-subset with `subset-font` before embedding — this
keeps each PDF around ~1.2 MB instead of ~7 MB.

## Files

- `render.mjs` — markdown → HTML → PDF pipeline.
- `theme.css` — the print stylesheet / design system.
- `fonts/` — the four OFL variable fonts.
- `rasterize.mjs` — dev helper: rasterize PDF pages to PNG for visual review
  (`node rasterize.mjs <pdf> <outDir> [1,2,5]`).
