import React, { useEffect, useState } from 'react'
import { api } from '../api.js'

const SEV_CLASS = { CRITICAL: 'bad', HIGH: 'bad', MEDIUM: 'PENDING', LOW: 'ok' }

export default function CertIn({ me }) {
  const [view, setView] = useState('dashboard')
  const isAdmin = me?.role === 'administrator'
  return (
    <div>
      <div className="row" style={{ marginBottom: 14 }}>
        <button className={'btn sm ' + (view === 'dashboard' ? '' : 'ghost')} onClick={() => setView('dashboard')}>Dashboard</button>
        <button className={'btn sm ' + (view === 'alerts' ? '' : 'ghost')} onClick={() => setView('alerts')}>Alerts</button>
        {isAdmin && <button className={'btn sm ' + (view === 'usage' ? '' : 'ghost')} onClick={() => setView('usage')}>Customer Usage</button>}
      </div>
      {view === 'dashboard' ? <Dash /> : view === 'usage' ? <Usage /> : <Alerts />}
    </div>
  )
}

function Usage() {
  const [items, setItems] = useState([])
  const [customers, setCustomers] = useState([])
  const [cid, setCid] = useState('')
  const [err, setErr] = useState('')
  const [entry, setEntry] = useState(null)
  const [busy, setBusy] = useState(false)

  async function openEntry(id) {
    setBusy(true); setErr('')
    try { setEntry(await api('GET', `/admin/api/certin/usage/${id}`)) }
    catch (e) { setErr(e.message) } finally { setBusy(false) }
  }

  async function load() {
    try {
      const r = await api('GET', `/admin/api/certin/usage?limit=200${cid ? `&customer_id=${cid}` : ''}`)
      setItems(r.items)
    } catch (e) { setErr(e.message) }
  }
  useEffect(() => {
    api('GET', '/admin/api/certin/customers').then(r => setCustomers(r.items)).catch(() => {})
  }, [])
  useEffect(() => { load(); const t = setInterval(load, 30000); return () => clearInterval(t) }, [cid])

  return (
    <div>
      <div className="row" style={{ justifyContent: 'space-between', marginBottom: 6 }}>
        <h2 style={{ margin: 0 }}>Customer usage</h2>
        <div className="row">
          <select value={cid} onChange={e => setCid(e.target.value)} style={{ maxWidth: 240 }}>
            <option value="">All customers</option>
            {customers.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
          <button className="btn sm ghost" onClick={load}>Refresh</button>
        </div>
      </div>
      <p className="muted" style={{ marginBottom: 10 }}>
        Every API call by CERT-In data customers: who fetched which resource and what was returned.
        Retained for 90 days.
      </p>
      {err && <div className="error">{err}</div>}
      <div className="card tablewrap">
        <table>
          <thead><tr><th>When</th><th>Customer</th><th>Resource fetched</th><th>Status</th><th>Response provided</th><th>IP</th><th></th></tr></thead>
          <tbody>
            {items.map(u => (
              <tr key={u.id}>
                <td className="muted" style={{ whiteSpace: 'nowrap' }}>{new Date(u.timestamp).toLocaleString()}</td>
                <td><b>{u.customer}</b></td>
                <td style={{ maxWidth: 240, wordBreak: 'break-all' }}>{u.resource}</td>
                <td>{u.status_code === 200 ? <span className="pill ok">200</span> : <span className="pill bad">{u.status_code}</span>}</td>
                <td className="muted" style={{ maxWidth: 280 }}>{u.response_summary}</td>
                <td className="muted">{u.ip_address}</td>
                <td><button className="btn sm ghost" disabled={busy} onClick={() => openEntry(u.id)}>View</button></td>
              </tr>
            ))}
            {!items.length && <tr><td colSpan={7} className="muted">No customer requests logged yet.</td></tr>}
          </tbody>
        </table>
      </div>
      {entry && <UsageDetail e={entry} onClose={() => setEntry(null)} />}
    </div>
  )
}

function UsageDetail({ e, onClose }) {
  const kb = e.response.size_bytes >= 1024 ? (e.response.size_bytes / 1024).toFixed(1) + ' KB' : e.response.size_bytes + ' B'
  return (
    <div className="modal-bg" onClick={onClose}>
      <div className="modal" style={{ width: 860 }} onClick={ev => ev.stopPropagation()}>
        <div className="row" style={{ justifyContent: 'space-between' }}>
          <h2 style={{ margin: 0 }}>Request #{e.id}</h2>
          {e.response.status_code === 200
            ? <span className="pill ok">200 OK</span>
            : <span className="pill bad">{e.response.status_code}</span>}
        </div>
        <div className="grid g2" style={{ marginTop: 10 }}>
          <div>
            <label>Customer</label>
            <p><b>{e.customer.name}</b> (id {e.customer.id}){e.customer.contact_email ? ` · ${e.customer.contact_email}` : ''}<br />
              <span className="muted">Rate limit {e.customer.rate_limit}/min · {e.customer.is_active ? 'active' : 'inactive'}</span></p>
            <label>When</label>
            <p>{new Date(e.timestamp).toLocaleString()}</p>
            <label>Source</label>
            <p>IP {e.request.ip_address || '—'}<br />
              <span className="muted" style={{ wordBreak: 'break-all' }}>{e.request.user_agent || 'no user agent'}</span></p>
          </div>
          <div>
            <label>Resource fetched</label>
            <p style={{ wordBreak: 'break-all' }}>{e.request.resource}</p>
            <label>Response</label>
            <p>{e.response.summary}<br />
              <span className="muted">{kb} · served in {e.response.duration_ms} ms</span></p>
          </div>
        </div>
        <label>Complete response body served to the customer</label>
        <pre style={{ background: '#f4f6f9', border: '1px solid #dde3ea', borderRadius: 4, padding: 10,
                      maxHeight: 320, overflow: 'auto', fontSize: 11, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
          {e.response.body ? (typeof e.response.body === 'string' ? e.response.body : JSON.stringify(e.response.body, null, 2)) : '(no body stored for this entry)'}
        </pre>
        <div className="row" style={{ marginTop: 12, justifyContent: 'flex-end' }}>
          <button className="btn ghost" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  )
}

function Dash() {
  const [s, setS] = useState(null)
  const [err, setErr] = useState('')
  useEffect(() => { api('GET', '/admin/api/certin/stats').then(setS).catch(e => setErr(e.message)) }, [])
  if (err) return <div className="error">{err}</div>
  if (!s) return <p className="muted">Loading…</p>

  const months = Object.entries(s.by_month || {})
  const thisMonth = months.length ? months[0][1].total : 0
  const years = Object.entries(s.by_year || {})

  return (
    <div>
      <h2>CERT-In dashboard</h2>
      <p className="muted" style={{ marginBottom: 10 }}>
        Publication activity of CERT-In (cert-in.org.in), indexed live.
        Last refresh {s.last_refresh ? new Date(s.last_refresh).toLocaleString() : '—'}.
      </p>
      <div className="card grid g4">
        <div className="stat"><div className="n">{s.total_alerts}</div><div className="l">Alerts indexed since 2003</div></div>
        <div className="stat"><div className="n">{s.by_type?.advisory || 0}</div><div className="l">Advisories</div></div>
        <div className="stat"><div className="n">{s.by_type?.vulnerability_note || 0}</div><div className="l">Vulnerability notes</div></div>
        <div className="stat"><div className="n">{thisMonth}</div><div className="l">Published this month</div></div>
      </div>
      <div className="grid g2">
        <div className="card">
          <h2 style={{ fontSize: 15 }}>Last 12 months</h2>
          <div className="tablewrap">
            <table>
              <thead><tr><th>Month</th><th>Advisories</th><th>Vuln notes</th><th>Total</th></tr></thead>
              <tbody>
                {months.map(([m, v]) => (
                  <tr key={m}><td>{m}</td><td>{v.advisories}</td><td>{v.vulnerability_notes}</td><td><b>{v.total}</b></td></tr>
                ))}
                {!months.length && <tr><td colSpan={4} className="muted">No dated alerts yet.</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
        <div className="card">
          <h2 style={{ fontSize: 15 }}>Archive by year</h2>
          <div className="tablewrap" style={{ maxHeight: 420, overflowY: 'auto' }}>
            <table>
              <thead><tr><th>Year</th><th>Alerts</th></tr></thead>
              <tbody>
                {years.map(([y, c]) => <tr key={y}><td>{y}</td><td>{c}</td></tr>)}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  )
}

function Alerts() {
  const [items, setItems] = useState([])
  const [total, setTotal] = useState(0)
  const [type, setType] = useState('')
  const [year, setYear] = useState('')
  const [q, setQ] = useState('')
  const [offset, setOffset] = useState(0)
  const [detail, setDetail] = useState(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const limit = 25

  async function load(off = 0) {
    setErr('')
    try {
      const params = new URLSearchParams()
      if (type) params.set('type', type)
      if (year) params.set('year', year)
      if (q) params.set('q', q)
      params.set('limit', limit); params.set('offset', off)
      const r = await api('GET', `/admin/api/certin/alerts?${params}`)
      setItems(r.items); setTotal(r.total); setOffset(off)
    } catch (e) { setErr(e.message) }
  }
  useEffect(() => { load(0) }, [type, year])

  async function openDetail(id) {
    setBusy(true); setErr('')
    try { setDetail(await api('GET', `/admin/api/certin/alerts/${id}`)) }
    catch (e) { setErr(e.message) } finally { setBusy(false) }
  }

  const years = []
  for (let y = new Date().getFullYear(); y >= 2003; y--) years.push(y)

  return (
    <div>
      <h2>CERT-In alerts</h2>
      {err && <div className="error">{err}</div>}
      <div className="card">
        <div className="row" style={{ marginBottom: 10 }}>
          <select value={type} onChange={e => setType(e.target.value)} style={{ maxWidth: 210 }}>
            <option value="">All types</option>
            <option value="advisory">Advisories (CIAD)</option>
            <option value="vulnerability_note">Vulnerability notes (CIVN)</option>
          </select>
          <select value={year} onChange={e => setYear(e.target.value)} style={{ maxWidth: 120 }}>
            <option value="">All years</option>
            {years.map(y => <option key={y} value={y}>{y}</option>)}
          </select>
          <input placeholder="Search title or id, e.g. Android" value={q} onChange={e => setQ(e.target.value)}
                 onKeyDown={e => e.key === 'Enter' && load(0)} style={{ maxWidth: 260 }} />
          <button className="btn sm" onClick={() => load(0)}>Search</button>
          <span className="muted">{total} alerts</span>
        </div>
        <div className="tablewrap">
          <table>
            <thead><tr><th>Alert</th><th>Type</th><th>Date</th><th>Title</th><th></th></tr></thead>
            <tbody>
              {items.map(a => (
                <tr key={a.id}>
                  <td><b>{a.id}</b></td>
                  <td>{a.type === 'advisory' ? 'Advisory' : 'Vuln note'}</td>
                  <td className="muted">{a.date || '—'}</td>
                  <td>{a.title}</td>
                  <td><button className="btn sm ghost" disabled={busy} onClick={() => openDetail(a.id)}>View</button></td>
                </tr>
              ))}
              {!items.length && <tr><td colSpan={5} className="muted">No alerts match.</td></tr>}
            </tbody>
          </table>
        </div>
        <div className="row" style={{ marginTop: 10 }}>
          <button className="btn sm ghost" disabled={offset === 0} onClick={() => load(Math.max(0, offset - limit))}>Previous</button>
          <span className="muted">{offset + 1} to {Math.min(offset + limit, total)}</span>
          <button className="btn sm ghost" disabled={offset + limit >= total} onClick={() => load(offset + limit)}>Next</button>
        </div>
      </div>

      {detail && (
        <div className="modal-bg" onClick={() => setDetail(null)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div className="row" style={{ justifyContent: 'space-between' }}>
              <h2 style={{ margin: 0 }}>{detail.id}</h2>
              {detail.severity && <span className={'pill ' + (SEV_CLASS[detail.severity] || 'PENDING')}>{detail.severity}</span>}
            </div>
            <p style={{ margin: '6px 0 10px', fontWeight: 600 }}>{detail.title}</p>
            {detail.date && <p className="muted">Issued {detail.date}</p>}
            {detail.cves?.length > 0 && (
              <p style={{ margin: '8px 0' }}>{detail.cves.map(c => (
                <a key={c} href={`https://nvd.nist.gov/vuln/detail/${c}`} target="_blank" rel="noreferrer"
                   style={{ marginRight: 8 }}>{c}</a>))}
              </p>
            )}
            {detail.software_affected && (<><label>Software affected</label><p>{detail.software_affected}</p></>)}
            {detail.overview && (<><label>Overview</label><p>{detail.overview}</p></>)}
            {detail.description && (<><label>Description</label><p style={{ maxHeight: 180, overflowY: 'auto' }}>{detail.description}</p></>)}
            {detail.solution && (<><label>Solution</label><p>{detail.solution}</p></>)}
            <div className="row" style={{ marginTop: 12, justifyContent: 'space-between' }}>
              <a href={detail.source_url} target="_blank" rel="noreferrer">View on cert-in.org.in</a>
              <button className="btn ghost" onClick={() => setDetail(null)}>Close</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
