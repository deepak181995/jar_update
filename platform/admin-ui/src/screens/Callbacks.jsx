import React, { useEffect, useState } from 'react'
import { api } from '../api.js'

export default function Callbacks({ me }) {
  const [items, setItems] = useState([])
  const [err, setErr] = useState('')
  const canWrite = me.role !== 'readonly'

  async function load() {
    try { setItems((await api('GET', '/admin/api/callbacks')).items) } catch (e) { setErr(e.message) }
  }
  useEffect(() => { load(); const t = setInterval(load, 30000); return () => clearInterval(t) }, [])

  async function retry(id) {
    try { await api('POST', `/admin/api/callbacks/${id}/retry`); load() } catch (e) { setErr(e.message) }
  }

  return (
    <div>
      <div className="row" style={{ justifyContent: 'space-between', marginBottom: 12 }}>
        <h2 style={{ margin: 0 }}>Callback deliveries</h2>
        <button className="btn ghost sm" onClick={load}>Refresh</button>
      </div>
      <p className="muted" style={{ marginBottom: 10 }}>
        Completed quotes are pushed automatically to each partner's registered callback URL,
        signed and retried up to five times. Failures appear here for manual retry.
      </p>
      {err && <div className="error">{err}</div>}
      <div className="card tablewrap">
        <table>
          <thead><tr><th>Reference</th><th>Partner</th><th>Status</th><th>Attempts</th><th>Last error</th><th>Delivered / next retry</th><th></th></tr></thead>
          <tbody>
            {items.map(d => (
              <tr key={d.id}>
                <td>{d.reference_number}</td>
                <td>{d.partner_name}</td>
                <td><span className={'pill ' + (d.status === 'DELIVERED' ? 'ok' : d.status === 'FAILED' ? 'bad' : 'PENDING')}>{d.status}</span></td>
                <td>{d.attempts}</td>
                <td className="muted" style={{ maxWidth: 260, wordBreak: 'break-all' }}>{d.last_error || '—'}</td>
                <td className="muted">{d.delivered_at ? new Date(d.delivered_at).toLocaleString() : d.next_retry_at ? new Date(d.next_retry_at).toLocaleString() : '—'}</td>
                <td>{canWrite && d.status !== 'DELIVERED' && <button className="btn sm" onClick={() => retry(d.id)}>Retry now</button>}</td>
              </tr>
            ))}
            {!items.length && <tr><td colSpan={7} className="muted">No callback deliveries yet. They appear when a quote is completed for a partner that has a callback URL configured.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  )
}
