import React, { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { apiFetch } from '../lib/apiBase'
import PageShell from './PageShell'

/**
 * Admin Management Dashboard - Enterprise User & Role Management
 * Unique IDs: adminmgmt-*
 */
export default function AdminManagement() {
  const navigate = useNavigate()
  const { session, isCeo } = useAuth()
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [successMsg, setSuccessMsg] = useState(null)

  // New user form state
  const [newEmail, setNewEmail] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [newRole, setNewRole] = useState('viewer')
  const [newIsSuperadmin, setNewIsSuperadmin] = useState(false)
  const [submitting, setSubmitting] = useState(false)

  // Edit user modal state
  const [editingUser, setEditingUser] = useState(null)
  const [editRole, setEditRole] = useState('')
  const [editIsSuperadmin, setEditIsSuperadmin] = useState(false)

  const loadUsers = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const r = await apiFetch('/api/admin/users')
      if (!r.ok) {
        const d = await r.json().catch(() => ({}))
        throw new Error(d.detail || `HTTP ${r.status}`)
      }
      const data = await r.json()
      setUsers(Array.isArray(data) ? data : data.users || [])
    } catch (err) {
      setError(err.message || 'Failed to load users')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadUsers()
  }, [loadUsers])

  const handleCreateUser = async (e) => {
    e.preventDefault()
    if (!newEmail.trim() || !newPassword.trim()) {
      setError('Email and password are required')
      return
    }
    setSubmitting(true)
    setError(null)
    setSuccessMsg(null)
    try {
      const r = await apiFetch('/api/admin/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: newEmail.trim(),
          password: newPassword,
          role: newRole,
          is_superadmin: newIsSuperadmin,
        }),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) {
        throw new Error(d.detail || 'Failed to create user')
      }
      setSuccessMsg(`User ${newEmail} created successfully`)
      setNewEmail('')
      setNewPassword('')
      setNewRole('viewer')
      setNewIsSuperadmin(false)
      await loadUsers()
    } catch (err) {
      setError(err.message)
    } finally {
      setSubmitting(false)
    }
  }

  const handleUpdateRole = async () => {
    if (!editingUser) return
    setSubmitting(true)
    setError(null)
    try {
      const r = await apiFetch(`/api/admin/users/${editingUser.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          role: editRole,
          is_superadmin: editIsSuperadmin,
        }),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) {
        throw new Error(d.detail || 'Failed to update user')
      }
      setSuccessMsg(`User ${editingUser.email} updated`)
      setEditingUser(null)
      await loadUsers()
    } catch (err) {
      setError(err.message)
    } finally {
      setSubmitting(false)
    }
  }

  const handleDeactivateUser = async (userId, email) => {
    if (!window.confirm(`Deactivate user ${email}?`)) return
    try {
      const r = await apiFetch(`/api/admin/users/${userId}/deactivate`, {
        method: 'POST',
      })
      if (!r.ok) {
        const d = await r.json().catch(() => ({}))
        throw new Error(d.detail || 'Failed to deactivate')
      }
      setSuccessMsg(`User ${email} deactivated`)
      await loadUsers()
    } catch (err) {
      setError(err.message)
    }
  }

  const openEditModal = (user) => {
    setEditingUser(user)
    setEditRole(user.role || 'viewer')
    setEditIsSuperadmin(user.is_superadmin || false)
  }

  if (!isCeo && !session?.is_superadmin) {
    return (
      <PageShell title="Admin Management" subtitle="User & Role Management">
        <div className="p-8 text-center">
          <div className="text-red-400 text-lg font-semibold mb-2">Access Denied</div>
          <p className="text-slate-400 text-sm">
            You need CEO or Superadmin privileges to access this page.
          </p>
        </div>
      </PageShell>
    )
  }

  return (
    <PageShell title="Admin Management" subtitle="Enterprise User & Role Management">
      <div className="p-6 max-w-6xl mx-auto space-y-8">
        {/* Success/Error Messages */}
        {successMsg && (
          <div
            id="adminmgmt-success-alert"
            className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 px-4 py-3 rounded-lg text-sm flex justify-between items-center"
          >
            <span>{successMsg}</span>
            <button
              id="adminmgmt-dismiss-success-btn"
              type="button"
              onClick={() => setSuccessMsg(null)}
              className="text-emerald-400 hover:text-emerald-300 ml-4"
            >
              ✕
            </button>
          </div>
        )}
        {error && (
          <div
            id="adminmgmt-error-alert"
            className="bg-red-500/10 border border-red-500/30 text-red-400 px-4 py-3 rounded-lg text-sm flex justify-between items-center"
          >
            <span>{error}</span>
            <button
              id="adminmgmt-dismiss-error-btn"
              type="button"
              onClick={() => setError(null)}
              className="text-red-400 hover:text-red-300 ml-4"
            >
              ✕
            </button>
          </div>
        )}

        {/* Create New User Section */}
        <section className="bg-black/30 border border-white/10 rounded-2xl p-6 backdrop-blur-md">
          <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <span className="text-cyan-400">+</span> Create New User
          </h2>
          <form onSubmit={handleCreateUser} className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <div>
              <label
                htmlFor="adminmgmt-new-email"
                className="block text-xs uppercase tracking-widest text-slate-500 mb-2"
              >
                Email
              </label>
              <input
                id="adminmgmt-new-email"
                type="email"
                value={newEmail}
                onChange={(e) => setNewEmail(e.target.value)}
                placeholder="user@example.com"
                required
                className="w-full px-3 py-2 rounded-lg bg-black/50 border border-white/15 text-white placeholder:text-slate-600 focus:border-cyan-500/50 focus:outline-none text-sm"
              />
            </div>
            <div>
              <label
                htmlFor="adminmgmt-new-password"
                className="block text-xs uppercase tracking-widest text-slate-500 mb-2"
              >
                Password
              </label>
              <input
                id="adminmgmt-new-password"
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="••••••••"
                required
                className="w-full px-3 py-2 rounded-lg bg-black/50 border border-white/15 text-white placeholder:text-slate-600 focus:border-cyan-500/50 focus:outline-none text-sm"
              />
            </div>
            <div>
              <label
                htmlFor="adminmgmt-new-role"
                className="block text-xs uppercase tracking-widest text-slate-500 mb-2"
              >
                Role
              </label>
              <select
                id="adminmgmt-new-role"
                value={newRole}
                onChange={(e) => setNewRole(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-black/50 border border-white/15 text-white focus:border-cyan-500/50 focus:outline-none text-sm"
              >
                <option value="viewer">Viewer</option>
                <option value="analyst">Analyst</option>
                <option value="operator">Operator</option>
                <option value="admin">Admin</option>
                <option value="ceo">CEO</option>
              </select>
            </div>
            <div className="flex flex-col justify-end">
              <label className="flex items-center gap-2 mb-2 cursor-pointer">
                <input
                  id="adminmgmt-new-superadmin"
                  type="checkbox"
                  checked={newIsSuperadmin}
                  onChange={(e) => setNewIsSuperadmin(e.target.checked)}
                  className="rounded border-white/20 bg-black/50 w-4 h-4 accent-amber-500"
                />
                <span className="text-xs text-amber-400 uppercase tracking-widest">Superadmin</span>
              </label>
              <button
                id="adminmgmt-create-user-btn"
                type="submit"
                disabled={submitting}
                className="px-4 py-2 rounded-lg font-semibold text-sm bg-cyan-500/20 border border-cyan-500/50 text-cyan-400 hover:bg-cyan-500/30 disabled:opacity-50 transition-colors"
              >
                {submitting ? 'Creating…' : 'Create User'}
              </button>
            </div>
          </form>
        </section>

        {/* Users List Section */}
        <section className="bg-black/30 border border-white/10 rounded-2xl p-6 backdrop-blur-md">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <span className="text-violet-400">◎</span> System Users
            </h2>
            <button
              id="adminmgmt-refresh-users-btn"
              type="button"
              onClick={loadUsers}
              disabled={loading}
              className="px-3 py-1.5 rounded-lg text-xs font-medium border border-white/20 text-slate-400 hover:bg-white/5 disabled:opacity-50"
            >
              {loading ? 'Loading…' : 'Refresh'}
            </button>
          </div>

          {loading && users.length === 0 ? (
            <div className="text-center py-8 text-slate-500">Loading users…</div>
          ) : users.length === 0 ? (
            <div className="text-center py-8 text-slate-500">No users found</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-white/10">
                    <th className="text-left py-3 px-2 text-xs uppercase tracking-widest text-slate-500 font-medium">
                      Email
                    </th>
                    <th className="text-left py-3 px-2 text-xs uppercase tracking-widest text-slate-500 font-medium">
                      Role
                    </th>
                    <th className="text-left py-3 px-2 text-xs uppercase tracking-widest text-slate-500 font-medium">
                      Status
                    </th>
                    <th className="text-left py-3 px-2 text-xs uppercase tracking-widest text-slate-500 font-medium">
                      Superadmin
                    </th>
                    <th className="text-right py-3 px-2 text-xs uppercase tracking-widest text-slate-500 font-medium">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((user, idx) => (
                    <tr
                      key={user.id || idx}
                      className="border-b border-white/5 hover:bg-white/5 transition-colors"
                    >
                      <td className="py-3 px-2 text-white font-mono">{user.email}</td>
                      <td className="py-3 px-2">
                        <span
                          className={`px-2 py-0.5 rounded text-xs font-medium uppercase ${
                            user.role === 'ceo'
                              ? 'bg-amber-500/20 text-amber-400'
                              : user.role === 'admin'
                              ? 'bg-violet-500/20 text-violet-400'
                              : user.role === 'operator'
                              ? 'bg-cyan-500/20 text-cyan-400'
                              : user.role === 'analyst'
                              ? 'bg-emerald-500/20 text-emerald-400'
                              : 'bg-slate-500/20 text-slate-400'
                          }`}
                        >
                          {user.role || 'viewer'}
                        </span>
                      </td>
                      <td className="py-3 px-2">
                        <span
                          className={`px-2 py-0.5 rounded text-xs font-medium ${
                            user.is_active !== false
                              ? 'bg-emerald-500/20 text-emerald-400'
                              : 'bg-red-500/20 text-red-400'
                          }`}
                        >
                          {user.is_active !== false ? 'Active' : 'Inactive'}
                        </span>
                      </td>
                      <td className="py-3 px-2">
                        {user.is_superadmin && (
                          <span className="text-amber-400 font-semibold">★</span>
                        )}
                      </td>
                      <td className="py-3 px-2 text-right space-x-2">
                        <button
                          id={`adminmgmt-edit-user-${user.id}-btn`}
                          type="button"
                          onClick={() => openEditModal(user)}
                          className="px-2 py-1 rounded text-xs border border-white/20 text-slate-400 hover:text-white hover:bg-white/10"
                        >
                          Edit
                        </button>
                        {user.is_active !== false && (
                          <button
                            id={`adminmgmt-deactivate-user-${user.id}-btn`}
                            type="button"
                            onClick={() => handleDeactivateUser(user.id, user.email)}
                            className="px-2 py-1 rounded text-xs border border-red-500/30 text-red-400 hover:bg-red-500/20"
                          >
                            Deactivate
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* Edit User Modal */}
        {editingUser && (
          <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
            <div className="bg-slate-900 border border-white/10 rounded-2xl p-6 w-full max-w-md">
              <h3 className="text-lg font-semibold text-white mb-4">
                Edit User: {editingUser.email}
              </h3>
              <div className="space-y-4">
                <div>
                  <label
                    htmlFor="adminmgmt-edit-role"
                    className="block text-xs uppercase tracking-widest text-slate-500 mb-2"
                  >
                    Role
                  </label>
                  <select
                    id="adminmgmt-edit-role"
                    value={editRole}
                    onChange={(e) => setEditRole(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-black/50 border border-white/15 text-white focus:border-cyan-500/50 focus:outline-none text-sm"
                  >
                    <option value="viewer">Viewer</option>
                    <option value="analyst">Analyst</option>
                    <option value="operator">Operator</option>
                    <option value="admin">Admin</option>
                    <option value="ceo">CEO</option>
                  </select>
                </div>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    id="adminmgmt-edit-superadmin"
                    type="checkbox"
                    checked={editIsSuperadmin}
                    onChange={(e) => setEditIsSuperadmin(e.target.checked)}
                    className="rounded border-white/20 bg-black/50 w-4 h-4 accent-amber-500"
                  />
                  <span className="text-sm text-amber-400">Grant Superadmin privileges</span>
                </label>
              </div>
              <div className="flex gap-3 mt-6">
                <button
                  id="adminmgmt-cancel-edit-btn"
                  type="button"
                  onClick={() => setEditingUser(null)}
                  className="flex-1 px-4 py-2 rounded-lg font-medium text-sm border border-white/20 text-slate-400 hover:bg-white/5"
                >
                  Cancel
                </button>
                <button
                  id="adminmgmt-save-edit-btn"
                  type="button"
                  onClick={handleUpdateRole}
                  disabled={submitting}
                  className="flex-1 px-4 py-2 rounded-lg font-semibold text-sm bg-cyan-500/20 border border-cyan-500/50 text-cyan-400 hover:bg-cyan-500/30 disabled:opacity-50"
                >
                  {submitting ? 'Saving…' : 'Save Changes'}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Quick Admin Actions */}
        <section className="bg-black/30 border border-white/10 rounded-2xl p-6 backdrop-blur-md">
          <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <span className="text-emerald-400">⚡</span> Quick Actions
          </h2>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <button
              id="adminmgmt-export-users-btn"
              type="button"
              onClick={() => {
                const csv = ['Email,Role,Superadmin,Active']
                  .concat(
                    users.map(
                      (u) =>
                        `${u.email},${u.role || 'viewer'},${u.is_superadmin ? 'yes' : 'no'},${
                          u.is_active !== false ? 'yes' : 'no'
                        }`
                    )
                  )
                  .join('\n')
                const blob = new Blob([csv], { type: 'text/csv' })
                const url = URL.createObjectURL(blob)
                const a = document.createElement('a')
                a.href = url
                a.download = 'weissman_users_export.csv'
                a.click()
                URL.revokeObjectURL(url)
              }}
              className="px-4 py-3 rounded-xl text-sm font-medium border border-white/15 bg-white/5 text-white/80 hover:bg-white/10 text-left"
            >
              📄 Export Users (CSV)
            </button>
            <button
              id="adminmgmt-audit-log-btn"
              type="button"
              onClick={() => navigate('/')}
              className="px-4 py-3 rounded-xl text-sm font-medium border border-white/15 bg-white/5 text-white/80 hover:bg-white/10 text-left"
            >
              📋 View Audit Logs
            </button>
            <button
              id="adminmgmt-sso-config-btn"
              type="button"
              onClick={() => navigate('/sso-config')}
              className="px-4 py-3 rounded-xl text-sm font-medium border border-white/15 bg-white/5 text-white/80 hover:bg-white/10 text-left"
            >
              🔑 SSO Configuration
            </button>
            <button
              id="adminmgmt-system-settings-btn"
              type="button"
              onClick={() => navigate('/')}
              className="px-4 py-3 rounded-xl text-sm font-medium border border-white/15 bg-white/5 text-white/80 hover:bg-white/10 text-left"
            >
              ⚙️ System Settings
            </button>
          </div>
        </section>
      </div>
    </PageShell>
  )
}
