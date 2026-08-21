import React, { useEffect, useState } from 'react'
import { api } from '../api.js'

const EMPTY = { name: '', callback_url: '', rate_limit: 60, environment: 'uat', is_active: true }

export default function Partners() {
  const [items, setItems] = useState([])
  const [edit, setEdit] = useState(null)
  const [keyInfo, setKeyInfo] = useState(null)
  const [err, setErr] = useState('')

  async function load() { try { setItems((await api('GET', '/admin/api/partners')).items) } catch (e) { setErr(e.message) } }
  useEffect(() => { load() }, [])

  async function genKey(p, rotate) {
    try {
      const r = await api('POST', `/admin/api/partners/${p.id}/generate-key?rotate=${rotate}`)
      setKeyInfo({ partner: p.name, ...r }); load()
    } catch (e) { setErr(e.message) }
  }

  return (
    <div>
      <div className="row" style={{ justifyContent: 'space-between', marginBottom: 6 }}>
        <h2 style={{ margin: 0 }}>Freight partners and keys</h2>
        <button className="btn accent" onClick={() => setEdit({ ...EMPTY })}>New partner</button>
      </div>
      <p className="muted" style={{ marginBottom: 12 }}>
        Marketplace partners of the freight Quotation API (/v1/quotes). Their keys open freight
        endpoints only. CERT-In data customers are managed separately under CERT-In Customers.
      </p>
      {err && <div className="error">{err}</div>}
      {keyInfo && (
        <div className="notice">
          <b>API key for {keyInfo.partner} (copy now, shown once):</b>
          <div className="secret">{keyInfo.api_key}</div>
          <b>Callback signing secret:</b>
          <div className="secret">{keyInfo.callback_secret}</div>
          <b>Request signing secret{keyInfo.signing_required ? ' (required: production account)' : ' (not required for UAT)'}:</b>
          <div className="secret">{keyInfo.api_signing_secret}</div>
          <button className="btn sm ghost" onClick={() => setKeyInfo(null)}>Dismiss</button>
        </div>
      )}
      <div className="card tablewrap">
        <table>
          <thead><tr><th>Name</th><th>Environment</th><th>Callback URL</th><th>Rate limit</th><th>Keys</th><th>Active</th><th></th></tr></thead>
          <tbody>
            {items.map(p => (
              <tr key={p.id}>
                <td><b>{p.name}</b></td>
                <td>{p.environment === 'production' ? <span className="pill ok">production · signed</span> : <span className="pill PENDING">UAT</span>}</td>
                <td className="muted">{p.callback_url || '—'}</td>
                <td>{p.rate_limit}/min</td>
                <td>{p.has_api_key ? 'primary' : 'none'}{p.has_secondary_key ? ' + old (rotation)' : ''}</td>
                <td>{p.is_active ? <span className="pill ok">yes</span> : <span className="pill bad">no</span>}</td>
                <td className="row">
                  <button className="btn sm ghost" onClick={() => setEdit(p)}>Edit</button>
                  <button className="btn sm" onClick={() => genKey(p, p.has_api_key)}>{p.has_api_key ? 'Rotate key' : 'Generate key'}</button>
                  {p.has_secondary_key && <button className="btn sm ghost" onClick={async () => { await api('POST', `/admin/api/partners/${p.id}/retire-old-key`); load() }}>Retire old key</button>}
                </td>
              </tr>
            ))}
            {!items.length && <tr><td colSpan={7} className="muted">No partners yet. Add Rafttaar.ai here when ready.</td></tr>}
          </tbody>
        </table>
      </div>
      {edit && <Modal p0={edit} onClose={ok => { setEdit(null); if (ok) load() }} />}
    </div>
  )
}

function Modal({ p0, onClose }) {
  const [f, setF] = useState(p0)
  const [err, setErr] = useState('')
  const set = k => e => setF({ ...f, [k]: e.target.type === 'checkbox' ? e.target.checked : e.target.value })

  async function submit(e) {
    e.preventDefault(); setErr('')
    const body = { name: f.name, callback_url: f.callback_url, rate_limit: parseInt(f.rate_limit) || 60, environment: f.environment || 'uat', is_active: f.is_active }
    try {
      if (p0.id) await api('PUT', `/admin/api/partners/${p0.id}`, body)
      else await api('POST', '/admin/api/partners', body)
      onClose(true)
    } catch (e2) { setErr(e2.message) }
  }

  return (
    <div className="modal-bg" onClick={() => onClose(false)}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <h2>{p0.id ? 'Edit partner' : 'New partner'}</h2>
        {err && <div className="error">{err}</div>}
        <form onSubmit={submit}>
          <label>Name</label><input value={f.name} onChange={set('name')} required />
          <label>Callback URL (HTTPS)</label><input value={f.callback_url} onChange={set('callback_url')} placeholder="https://partner.example/webhooks/gec" />
          <label>Rate limit (requests per minute)</label><input type="number" min="1" value={f.rate_limit} onChange={set('rate_limit')} />
          <label>Environment</label>
          <select value={f.environment || 'uat'} onChange={set('environment')}>
            <option value="uat">UAT (unsigned requests allowed)</option>
            <option value="production">Production (signed requests required)</option>
          </select>
          <div className="row" style={{ marginTop: 10 }}>
            <label style={{ margin: 0 }}><input type="checkbox" checked={f.is_active} onChange={set('is_active')} style={{ width: 'auto', marginRight: 6 }} />Active</label>
          </div>
          <div className="row" style={{ marginTop: 14, justifyContent: 'flex-end' }}>
            <button type="button" className="btn ghost" onClick={() => onClose(false)}>Cancel</button>
            <button className="btn accent">Save</button>
          </div>
        </form>
      </div>
    </div>
  )
}
