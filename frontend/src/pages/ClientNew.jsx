import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'

export default function ClientNew() {
  const navigate = useNavigate()
  const [formData, setFormData] = useState({
    name: '',
    contact_email: '',
    domains: '',
    ip_ranges: '',
    tech_stack: '',
    auto_detect_tech_stack: true,
  })
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')

  function handleChange(e) {
    const { name, value, type, checked } = e.target
    setFormData((prev) => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value,
    }))
  }

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')

    // Validation
    if (!formData.name.trim()) {
      setError('Client name is required')
      return
    }
    if (!formData.contact_email.trim()) {
      setError('Contact email is required')
      return
    }
    if (!formData.domains.trim()) {
      setError('At least one domain must be specified for authorized scope')
      return
    }

    // Parse arrays
    const domains = formData.domains
      .split(/[\n,]+/)
      .map((d) => d.trim())
      .filter(Boolean)

    const ip_ranges = formData.ip_ranges
      .split(/[\n,]+/)
      .map((ip) => ip.trim())
      .filter(Boolean)

    const tech_stack = formData.tech_stack
      .split(/[\n,]+/)
      .map((t) => t.trim())
      .filter(Boolean)

    if (domains.length === 0) {
      setError('At least one valid domain is required')
      return
    }

    setSubmitting(true)

    try {
      const payload = {
        name: formData.name.trim(),
        contact_email: formData.contact_email.trim(),
        domains: JSON.stringify(domains),
        ip_ranges: JSON.stringify(ip_ranges),
        tech_stack: JSON.stringify(tech_stack),
        auto_detect_tech_stack: formData.auto_detect_tech_stack,
        client_configs: JSON.stringify({
          enabled_engines: [
            'osint',
            'asm',
            'supply_chain',
            'leak_hunter',
            'bola_idor',
            'ollama_fuzz',
            'semantic_ai_fuzz',
            'microsecond_timing',
            'ai_adversarial_redteam',
          ],
          roe_mode: 'safe_proofs',
          stealth_level: 50,
        }),
      }

      const response = await apiFetch('/api/clients', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      })

      if (!response.ok) {
        const text = await response.text().catch(() => 'Failed to create client')
        setError(`Failed to create client: ${text}`)
        setSubmitting(false)
        return
      }

      const data = await response.json()
      const clientId = data.id || data.client_id

      // Redirect to client detail page
      navigate(clientId ? `/clients/${clientId}` : '/clients')
    } catch (err) {
      setError(`Error creating client: ${err.message}`)
      setSubmitting(false)
    }
  }

  return (
    <PageShell
      title="Add New Client"
      subtitle="Onboard a new client organization with authorized scanning scope"
    >
      <div className="max-w-3xl mx-auto">
        <form onSubmit={handleSubmit} className="space-y-8">
          {/* Error Display */}
          {error && (
            <div className="p-4 bg-red-900/20 border border-red-500/30 rounded-lg text-red-400">
              {error}
            </div>
          )}

          {/* Section 1: Basic Information */}
          <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-white mb-4">Basic Information</h3>
            <div className="space-y-4">
              <div>
                <label htmlFor="name" className="block text-sm font-medium text-slate-300 mb-2">
                  Client Name <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  id="name"
                  name="name"
                  value={formData.name}
                  onChange={handleChange}
                  required
                  className="w-full px-4 py-2 bg-slate-900 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-purple-500"
                  placeholder="e.g., Acme Corporation"
                />
              </div>

              <div>
                <label htmlFor="contact_email" className="block text-sm font-medium text-slate-300 mb-2">
                  Contact Email <span className="text-red-400">*</span>
                </label>
                <input
                  type="email"
                  id="contact_email"
                  name="contact_email"
                  value={formData.contact_email}
                  onChange={handleChange}
                  required
                  className="w-full px-4 py-2 bg-slate-900 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-purple-500"
                  placeholder="security@example.com"
                />
              </div>
            </div>
          </div>

          {/* Section 2: Authorized Scope */}
          <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-white mb-2">Authorized Scanning Scope</h3>
            <p className="text-sm text-slate-400 mb-4">
              Define the authorized domains and IP ranges for security scanning. Only assets within this scope will be scanned.
            </p>

            <div className="space-y-4">
              <div>
                <label htmlFor="domains" className="block text-sm font-medium text-slate-300 mb-2">
                  Authorized Domains <span className="text-red-400">*</span>
                </label>
                <textarea
                  id="domains"
                  name="domains"
                  value={formData.domains}
                  onChange={handleChange}
                  required
                  rows={4}
                  className="w-full px-4 py-2 bg-slate-900 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-purple-500 font-mono text-sm"
                  placeholder="example.com&#10;*.example.com&#10;api.example.com"
                />
                <p className="mt-1 text-xs text-slate-500">One domain per line or comma-separated. Wildcards (*) supported.</p>
              </div>

              <div>
                <label htmlFor="ip_ranges" className="block text-sm font-medium text-slate-300 mb-2">
                  Authorized IP Ranges <span className="text-slate-500">(Optional)</span>
                </label>
                <textarea
                  id="ip_ranges"
                  name="ip_ranges"
                  value={formData.ip_ranges}
                  onChange={handleChange}
                  rows={3}
                  className="w-full px-4 py-2 bg-slate-900 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-purple-500 font-mono text-sm"
                  placeholder="192.168.1.0/24&#10;10.0.0.0/8"
                />
                <p className="mt-1 text-xs text-slate-500">CIDR notation supported. One range per line or comma-separated.</p>
              </div>
            </div>
          </div>

          {/* Section 3: Tech Stack */}
          <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-white mb-2">Technology Stack</h3>
            <p className="text-sm text-slate-400 mb-4">
              Specify known technologies for more accurate vulnerability correlation, or enable auto-detection.
            </p>

            <div className="space-y-4">
              <div className="flex items-center">
                <input
                  type="checkbox"
                  id="auto_detect_tech_stack"
                  name="auto_detect_tech_stack"
                  checked={formData.auto_detect_tech_stack}
                  onChange={handleChange}
                  className="w-4 h-4 text-purple-600 bg-slate-900 border-slate-600 rounded focus:ring-purple-500"
                />
                <label htmlFor="auto_detect_tech_stack" className="ml-2 text-sm text-slate-300">
                  Auto-detect technologies during scans (Recommended)
                </label>
              </div>

              <div>
                <label htmlFor="tech_stack" className="block text-sm font-medium text-slate-300 mb-2">
                  Known Technologies <span className="text-slate-500">(Optional)</span>
                </label>
                <textarea
                  id="tech_stack"
                  name="tech_stack"
                  value={formData.tech_stack}
                  onChange={handleChange}
                  rows={3}
                  className="w-full px-4 py-2 bg-slate-900 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-purple-500 font-mono text-sm"
                  placeholder="nginx&#10;php 8.1&#10;wordpress&#10;mysql"
                />
                <p className="mt-1 text-xs text-slate-500">Specify known software/versions. One per line or comma-separated.</p>
              </div>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center justify-between pt-6 border-t border-slate-700">
            <button
              type="button"
              onClick={() => navigate('/clients')}
              className="px-6 py-2 border border-slate-600 text-slate-300 rounded-lg hover:bg-slate-800 transition-colors"
              disabled={submitting}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="px-6 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors font-medium"
            >
              {submitting ? (
                <>
                  <span className="inline-block w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2" />
                  Creating...
                </>
              ) : (
                'Create Client'
              )}
            </button>
          </div>
        </form>
      </div>
    </PageShell>
  )
}
