import React, { useEffect, useState } from 'react'
import { api } from '../api.js'

export default function Audit() {
  const [items, setItems] = useState([])
  const [action, setAction] = useState('')
  const [err, setErr] = useState('')

  useEffect(() => {
    api('GET', `/admin/api/audit?action=${encodeURIComponent(action)}`)
      .then(r => setItems(r.items)).catch(e => setErr(e.message))
  }, [action])

  return (
    <div>
      <div className="row" style={{ justifyContent: 'space-between', marginBottom: 12 }}>
        <h2 style={{ margin: 0 }}>Audit log</h2>
        <input placeholder="Filter by action, e.g. rate_updated" value={action} onChange={e => setAction(e.target.value)} style={{ maxWidth: 280 }} />
      </div>
      {err && <div className="error">{err}</div>}
      <div className="card tablewrap">
        <table>
          <thead><tr><th>When</th><th>User</th><th>Action</th><th>Entity</th><th>Change</th><th>IP</th></tr></thead>
          <tbody>
            {items.map(a => (
              <tr key={a.id}>
                <td className="muted">{new Date(a.timestamp).toLocaleString()}</td>
                <td>{a.user_email || '—'}</td>
                <td><b>{a.action}</b></td>
                <td>{a.entity_type} {a.entity_id}</td>
                <td className="muted" style={{ maxWidth: 380, wordBreak: 'break-all' }}>
                  {a.old_value && <div>old: {a.old_value.slice(0, 160)}</div>}
                  {a.new_value && <div>new: {a.new_value.slice(0, 160)}</div>}
                </td>
                <td className="muted">{a.ip_address}</td>
              </tr>
            ))}
            {!items.length && <tr><td colSpan={6} className="muted">No entries.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  )
}
