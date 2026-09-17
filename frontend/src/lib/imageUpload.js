/**
 * Read an image File, downscale it in-browser, and return a compact
 * `data:image/jpeg;base64,...` URL suitable for POSTing to the avatar/logo
 * endpoints. Keeping the encode client-side means no object storage is needed
 * and the payload stays well under the API's size cap.
 */

function loadImage(src) {
  return new Promise((resolve, reject) => {
    const img = new Image()
    img.onload = () => resolve(img)
    img.onerror = () => reject(new Error('That file is not a valid image'))
    img.src = src
  })
}

function readFile(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(String(reader.result || ''))
    reader.onerror = () => reject(new Error('Could not read the file'))
    reader.readAsDataURL(file)
  })
}

/**
 * @param {File} file
 * @param {{maxDim?:number, quality?:number, maxBytes?:number}} opts
 * @returns {Promise<string>} a data:image/jpeg URL
 */
export async function fileToDataUrl(file, { maxDim = 256, quality = 0.85, maxBytes = 850_000 } = {}) {
  if (!file || !String(file.type || '').startsWith('image/')) {
    throw new Error('Please choose an image file')
  }
  const raw = await readFile(file)
  const img = await loadImage(raw)
  const scale = Math.min(1, maxDim / Math.max(img.width || maxDim, img.height || maxDim))
  const w = Math.max(1, Math.round((img.width || maxDim) * scale))
  const h = Math.max(1, Math.round((img.height || maxDim) * scale))
  const canvas = document.createElement('canvas')
  canvas.width = w
  canvas.height = h
  const ctx = canvas.getContext('2d')
  if (!ctx) throw new Error('Image processing is not supported in this browser')
  ctx.drawImage(img, 0, 0, w, h)

  let q = quality
  let out = canvas.toDataURL('image/jpeg', q)
  while (out.length > maxBytes && q > 0.4) {
    q -= 0.1
    out = canvas.toDataURL('image/jpeg', q)
  }
  if (out.length > maxBytes) {
    throw new Error('Image is too large — try a smaller one')
  }
  return out
}
