import { describe, it, expect } from 'vitest'
import { mountForensicShadow } from './forensicShadowHost.js'
describe('forensicShadowHost', () => {
  it('mounts closed shadow', () => {
    const host = document.createElement('div')
    document.body.appendChild(host)
    const shadow = mountForensicShadow(host, '<span class="forensic-badge">ok</span>')
    expect(shadow).toBeTruthy()
    host.remove()
  })
})