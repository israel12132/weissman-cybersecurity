import fs from 'node:fs'
import * as mupdf from 'mupdf'
const [pdfPath, outDir, pagesArg] = process.argv.slice(2)
fs.mkdirSync(outDir, { recursive: true })
const data = fs.readFileSync(pdfPath)
const doc = mupdf.Document.openDocument(data, 'application/pdf')
const n = doc.countPages()
const pages = pagesArg ? pagesArg.split(',').map(x=>parseInt(x,10)) : [...Array(n).keys()].map(i=>i+1)
const zoom = 132/72 // ~132 dpi
for (const p of pages) {
  if (p < 1 || p > n) continue
  const page = doc.loadPage(p-1)
  const pix = page.toPixmap(mupdf.Matrix.scale(zoom, zoom), mupdf.ColorSpace.DeviceRGB, false, true)
  const png = pix.asPNG()
  fs.writeFileSync(`${outDir}/p${String(p).padStart(2,'0')}.png`, png)
}
console.log(`pages=${n} rasterized=${pages.length}`)
