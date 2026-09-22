// Client-side PDF export — no external libraries, CSP-safe.
//
// Two builders:
//   * buildSimpleTextPdf — a tiny text PDF using the built-in Helvetica. Latin
//     only (Helvetica has no Hebrew glyphs), kept as a dependency-free fallback.
//   * renderTextPdf — the router used by the app. When the content contains
//     Hebrew/Arabic and a browser canvas is available, it rasterizes the text
//     (the browser shapes RTL/complex scripts correctly) and embeds it as a
//     full-page JPEG image, so Hebrew reports render properly. Otherwise it
//     falls back to buildSimpleTextPdf.

const RTL_RE = /[֐-׿؀-ۿ܀-ݏ]/ // Hebrew, Arabic, Syriac

function escapePdfText(s) {
  return String(s)
    .replace(/\\/g, '\\\\')
    .replace(/\(/g, '\\(')
    .replace(/\)/g, '\\)')
}

// PDF /Length and xref offsets must be byte counts, not UTF-16 code-unit counts.
// A JS string's `.length` diverges from the encoded byte length for any
// non-ASCII character (e.g. ≥ · → in engine/finding text), which would emit a
// wrong stream /Length and startxref and corrupt the file for strict parsers.
const PDF_ENCODER = new TextEncoder()
function byteLen(s) {
  return PDF_ENCODER.encode(s).length
}

export function buildSimpleTextPdf(lines) {
  const safeLines = (Array.isArray(lines) ? lines : [String(lines || '')])
    .slice(0, 120)
    .map((l) => escapePdfText(String(l).slice(0, 120)))

  const contentLines = ['BT', '/F1 11 Tf', '50 790 Td']
  for (let i = 0; i < safeLines.length; i += 1) {
    if (i > 0) contentLines.push('0 -14 Td')
    contentLines.push(`(${safeLines[i]}) Tj`)
  }
  contentLines.push('ET')
  const stream = contentLines.join('\n')

  const objects = []
  objects.push('1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj')
  objects.push('2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj')
  objects.push('3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj')
  objects.push('4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj')
  objects.push(`5 0 obj << /Length ${byteLen(stream)} >> stream\n${stream}\nendstream endobj`)

  let pdf = '%PDF-1.4\n'
  const offsets = [0]
  for (const obj of objects) {
    offsets.push(byteLen(pdf))
    pdf += `${obj}\n`
  }
  const xrefStart = byteLen(pdf)
  pdf += `xref\n0 ${objects.length + 1}\n`
  pdf += '0000000000 65535 f \n'
  for (let i = 1; i < offsets.length; i += 1) {
    pdf += `${String(offsets[i]).padStart(10, '0')} 00000 n \n`
  }
  pdf += `trailer << /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF`

  return new TextEncoder().encode(pdf)
}

/** True when any line contains RTL/complex-script text Helvetica cannot render. */
export function needsUnicodePdf(lines) {
  const arr = Array.isArray(lines) ? lines : [String(lines ?? '')]
  return arr.some((l) => RTL_RE.test(String(l ?? '')))
}

const enc = (s) => new TextEncoder().encode(s)

function concatBytes(chunks) {
  let total = 0
  for (const c of chunks) total += c.length
  const out = new Uint8Array(total)
  let off = 0
  for (const c of chunks) {
    out.set(c, off)
    off += c.length
  }
  return out
}

function base64ToBytes(b64) {
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i)
  return out
}

// Rasterize logical lines into one-or-more full-page JPEG images with the
// browser canvas (correct RTL/complex-script shaping). Throws when no 2D canvas
// context is available (headless/jsdom) so the caller can fall back.
function rasterizeLinesToPages(lines) {
  const scale = 2
  const pageW = 595
  const pageH = 842
  const W = pageW * scale
  const H = pageH * scale
  const margin = 40 * scale
  const fontSize = 13 * scale
  const lineHeight = Math.round(fontSize * 1.5)
  const usableW = W - margin * 2
  const linesPerPage = Math.max(1, Math.floor((H - margin * 2) / lineHeight))
  const font = `${fontSize}px sans-serif`

  const probeCanvas = document.createElement('canvas')
  const probe = probeCanvas.getContext('2d')
  if (!probe) throw new Error('2D canvas unavailable')
  probe.font = font

  // Word-wrap each logical line to the usable width; hard-break long tokens.
  const wrapped = []
  for (const raw of lines) {
    const text = String(raw ?? '')
    if (text === '') {
      wrapped.push('')
      continue
    }
    const words = text.split(/(\s+)/)
    let cur = ''
    for (const w of words) {
      const test = cur + w
      if (probe.measureText(test).width > usableW && cur.trim()) {
        wrapped.push(cur)
        cur = w.replace(/^\s+/, '')
      } else {
        cur = test
      }
    }
    if (cur !== '') wrapped.push(cur)
  }

  const pages = []
  const chunkCount = Math.max(1, Math.ceil(wrapped.length / linesPerPage))
  for (let c = 0; c < chunkCount; c += 1) {
    const chunk = wrapped.slice(c * linesPerPage, (c + 1) * linesPerPage)
    const canvas = document.createElement('canvas')
    canvas.width = W
    canvas.height = H
    const ctx = canvas.getContext('2d')
    if (!ctx) throw new Error('2D canvas unavailable')
    ctx.fillStyle = '#ffffff'
    ctx.fillRect(0, 0, W, H)
    ctx.fillStyle = '#111111'
    ctx.font = font
    ctx.textBaseline = 'top'
    let y = margin
    for (const line of chunk) {
      if (RTL_RE.test(line)) {
        ctx.direction = 'rtl'
        ctx.textAlign = 'right'
        ctx.fillText(line, W - margin, y)
      } else {
        ctx.direction = 'ltr'
        ctx.textAlign = 'left'
        ctx.fillText(line, margin, y)
      }
      y += lineHeight
    }
    const dataUrl = canvas.toDataURL('image/jpeg', 0.9)
    const b64 = (dataUrl.split(',')[1] || '').trim()
    if (!b64) throw new Error('canvas encode failed')
    pages.push({ bytes: base64ToBytes(b64), width: W, height: H })
  }
  return pages
}

/**
 * Assemble a PDF whose pages are full-page JPEG images (DCTDecode). Pure and
 * deterministic — exported so the byte assembly is unit-testable without a canvas.
 * @param {Array<{bytes: Uint8Array, width: number, height: number}>} pages
 */
export function assembleImagePdf(pages) {
  const list = Array.isArray(pages) && pages.length ? pages : []
  if (!list.length) return buildSimpleTextPdf([''])
  const pageW = 595
  const pageH = 842
  const n = list.length
  const imgNum = (p) => 3 + p * 3
  const contentNum = (p) => 4 + p * 3
  const pageNum = (p) => 5 + p * 3
  const kids = list.map((_, p) => `${pageNum(p)} 0 R`).join(' ')

  const parts = []
  parts.push({ num: 1, bytes: enc('1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n') })
  parts.push({
    num: 2,
    bytes: enc(`2 0 obj\n<< /Type /Pages /Kids [${kids}] /Count ${n} >>\nendobj\n`),
  })
  list.forEach((pg, p) => {
    const img = pg.bytes
    const head = enc(
      `${imgNum(p)} 0 obj\n<< /Type /XObject /Subtype /Image /Width ${pg.width} /Height ${pg.height} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length ${img.length} >>\nstream\n`,
    )
    const tail = enc('\nendstream\nendobj\n')
    parts.push({ num: imgNum(p), bytes: concatBytes([head, img, tail]) })

    const content = `q ${pageW} 0 0 ${pageH} 0 0 cm /Im0 Do Q`
    parts.push({
      num: contentNum(p),
      bytes: enc(
        `${contentNum(p)} 0 obj\n<< /Length ${content.length} >>\nstream\n${content}\nendstream\nendobj\n`,
      ),
    })
    parts.push({
      num: pageNum(p),
      bytes: enc(
        `${pageNum(p)} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${pageW} ${pageH}] /Resources << /XObject << /Im0 ${imgNum(p)} 0 R >> >> /Contents ${contentNum(p)} 0 R >>\nendobj\n`,
      ),
    })
  })

  parts.sort((a, b) => a.num - b.num)
  const header = enc('%PDF-1.4\n')
  const chunks = [header]
  let offset = header.length
  const offsets = []
  for (const part of parts) {
    offsets[part.num] = offset
    chunks.push(part.bytes)
    offset += part.bytes.length
  }
  const objCount = parts.length + 1
  const xrefStart = offset
  let xref = `xref\n0 ${objCount}\n0000000000 65535 f \n`
  for (let num = 1; num < objCount; num += 1) {
    xref += `${String(offsets[num] || 0).padStart(10, '0')} 00000 n \n`
  }
  xref += `trailer\n<< /Size ${objCount} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF`
  chunks.push(enc(xref))
  return concatBytes(chunks)
}

/**
 * The app-facing text→PDF entry point. Renders Hebrew/RTL content as an embedded
 * image (browser canvas) so it is legible; falls back to the Latin text PDF for
 * plain Latin content or when no canvas is available.
 */
export function renderTextPdf(lines) {
  const arr = Array.isArray(lines) ? lines : [String(lines ?? '')]
  if (
    needsUnicodePdf(arr) &&
    typeof document !== 'undefined' &&
    typeof document.createElement === 'function' &&
    typeof atob === 'function'
  ) {
    try {
      return assembleImagePdf(rasterizeLinesToPages(arr))
    } catch {
      // Canvas unavailable (headless/jsdom) — fall back to the Latin text PDF.
    }
  }
  return buildSimpleTextPdf(arr)
}

export function downloadBytes(bytes, fileName, mimeType) {
  const blob = new Blob([bytes], { type: mimeType })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = fileName
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}
