import React, { useEffect, useState } from 'react'
import { api } from '../api.js'

const SEV_CLASS = { CRITICAL: 'bad', HIGH: 'bad', MEDIUM: 'PENDING', LOW: 'ok' }

export default function CertIn() {
  const [stats, setStats] = useState(null)
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

  useEffect(() => {
    api('GET', '/admin/api/certin/stats').then(setStats).catch(() => {})
    load(0)
  }, [type, year])

  async function openDetail(id) {
    setBusy(true); setErr('')
    try { setDetail(await api('GET', `/admin/api/certin/alerts/${id}`)) }
    catch (e) { setErr(e.message) } finally { setBusy(false) }
  }

  const years = []
  for (let y = new Date().getFullYear(); y >= 2003; y--) years.push(y)

  return (
    <div>
      <h2>CERT-In security alerts</h2>
      <p className="muted" style={{ marginBottom: 10 }}>
        Live index of advisories and vulnerability notes published by CERT-In (cert-in.org.in),
        refreshed every 30 minutes. Click an alert for full detail.
      </p>
      {stats && (
        <div className="card grid g4">
          <div className="stat"><div className="n">{stats.total_alerts}</div><div className="l">Alerts indexed</div></div>
          <div className="stat"><div className="n">{stats.by_type?.advisory || 0}</div><div className="l">Advisories</div></div>
          <div className="stat"><div className="n">{stats.by_type?.vulnerability_note || 0}</div><div className="l">Vulnerability notes</div></div>
          <div className="stat"><div className="n">{stats.all_years_indexed ? 'Complete' : 'Backfilling'}</div><div className="l">Archive since 2003</div></div>
        </div>
      )}
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
