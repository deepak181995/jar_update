import React, { useEffect, useState } from 'react'
import { api } from '../api.js'
import { QuoteEntryModal } from './Quotes.jsx'

export function Countdown({ deadline }) {
  const [, tick] = useState(0)
  useEffect(() => { const t = setInterval(() => tick(x => x + 1), 30000); return () => clearInterval(t) }, [])
  if (!deadline) return <span className="muted">no deadline</span>
  const ms = new Date(deadline) - Date.now()
  const overdue = ms < 0
  const abs = Math.abs(ms)
  const h = Math.floor(abs / 3600000), m = Math.floor((abs % 3600000) / 60000)
  const cls = overdue ? 'red' : ms < 3600000 ? 'red' : ms < 4 * 3600000 ? 'amber' : 'green'
  return <span className={'count ' + cls}>{overdue ? 'OVERDUE by ' : ''}{h}h {m}m{overdue ? '' : ' left'}</span>
}

export default function Dashboard({ me }) {
  const [summary, setSummary] = useState(null)
  const [pending, setPending] = useState([])
  const [entry, setEntry] = useState(null)
  const [err, setErr] = useState('')
  const canWrite = me.role !== 'readonly'

  async function load() {
    try {
      const [s, p] = await Promise.all([
        api('GET', '/admin/api/reports/summary'),
        api('GET', '/admin/api/quotes/pending'),
      ])
      setSummary(s); setPending(p.items)
    } catch (e) { setErr(e.message) }
  }
  useEffect(() => { load(); const t = setInterval(load, 60000); return () => clearInterval(t) }, [])

  return (
    <div>
      <h2>Operations dashboard</h2>
      {err && <div className="error">{err}</div>}
      {summary && (
        <div className="card grid g4">
          <div className="stat"><div className="n">{summary.pending}</div><div className="l">Pending quotes</div></div>
          <div className="stat"><div className="n">{summary.sla_compliance_pct}%</div><div className="l">SLA compliance</div></div>
          <div className="stat"><div className="n">{summary.active_rates}</div><div className="l">Active rates</div></div>
          <div className="stat"><div className="n">{summary.rates_expiring_7d}</div><div className="l">Rates expiring in 7 days</div></div>
        </div>
      )}
      <div className="card">
        <div className="row" style={{ justifyContent: 'space-between' }}>
          <h2 style={{ margin: 0 }}>Pending quote requests by deadline</h2>
          <button className="btn ghost sm" onClick={load}>Refresh</button>
        </div>
        <div className="tablewrap">
          <table>
            <thead><tr><th>Reference</th><th>Route</th><th>Mode</th><th>Cargo</th><th>Tier</th><th>SLA</th>{canWrite && <th></th>}</tr></thead>
            <tbody>
              {pending.map(q => (
                <tr key={q.id}>
                  <td>{q.reference_number}</td>
                  <td>{q.origin_port} → {q.destination_port}, {q.destination_country}</td>
                  <td>{q.mode}</td>
                  <td>{q.cargo_description?.slice(0, 60)}</td>
                  <td className="muted">{q.sla_tier}</td>
                  <td><Countdown deadline={q.sla_deadline} /></td>
                  {canWrite && <td><button className="btn sm accent" onClick={() => setEntry(q)}>Enter quote</button></td>}
                </tr>
              ))}
              {!pending.length && <tr><td colSpan={7} className="muted">Nothing pending. All caught up.</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
      {entry && <QuoteEntryModal request={entry} onClose={ok => { setEntry(null); if (ok) load() }} />}
    </div>
  )
}
