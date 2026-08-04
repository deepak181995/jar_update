import React, { useEffect, useState } from 'react'
import { api } from '../api.js'

export default function Reports({ me }) {
  const [s, setS] = useState(null)
  const [margins, setMargins] = useState(null)
  const [err, setErr] = useState('')

  useEffect(() => {
    api('GET', '/admin/api/reports/summary').then(setS).catch(e => setErr(e.message))
    if (me.role === 'administrator') {
      api('GET', '/admin/api/reports/margin-by-route').then(r => setMargins(r.items)).catch(() => {})
    }
  }, [])

  return (
    <div>
      <h2>Reports</h2>
      {err && <div className="error">{err}</div>}
      {s && (
        <>
          <div className="card grid g4">
            <div className="stat"><div className="n">{s.total_requests}</div><div className="l">Quote requests (all time)</div></div>
            <div className="stat"><div className="n">{s.month_requests}</div><div className="l">Requests this month</div></div>
            <div className="stat"><div className="n">{s.quoted}</div><div className="l">Quoted</div></div>
            <div className="stat"><div className="n">{s.pending}</div><div className="l">Pending</div></div>
          </div>
          <div className="card grid g4">
            <div className="stat"><div className="n">{s.sla_compliance_pct}%</div><div className="l">SLA compliance</div></div>
            <div className="stat"><div className="n">{s.conversion_pct}%</div><div className="l">Quote to booking conversion</div></div>
            <div className="stat"><div className="n">{s.active_rates}</div><div className="l">Active rates</div></div>
            <div className="stat"><div className="n">{s.rates_expiring_7d}</div><div className="l">Expiring in 7 days</div></div>
          </div>
        </>
      )}
      {margins && (
        <div className="card">
          <h2>Average margin by destination <span className="muted">(administrator only)</span></h2>
          <div className="tablewrap">
            <table>
              <thead><tr><th>Destination country</th><th>Active rates</th><th>Average margin</th></tr></thead>
              <tbody>
                {margins.map((m, i) => (
                  <tr key={i}><td>{m.destination_country}</td><td>{m.rate_count}</td><td>{m.avg_margin.toFixed(2)}</td></tr>
                ))}
                {!margins.length && <tr><td colSpan={3} className="muted">No active rates yet.</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
