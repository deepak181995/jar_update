import React, { useEffect, useState } from 'react'
import { api } from '../api.js'

const EMPTY = { name: '', contact_email: '', rate_limit: 120, is_active: true }

export default function CertinCustomers() {
  const [items, setItems] = useState([])
  const [edit, setEdit] = useState(null)
  const [keyInfo, setKeyInfo] = useState(null)
  const [err, setErr] = useState('')

  async function load() {
    try { setItems((await api('GET', '/admin/api/certin/customers')).items) } catch (e) { setErr(e.message) }
  }
  useEffect(() => { load() }, [])

  async function genKey(c, rotate) {
    try {
      const r = await api('POST', `/admin/api/certin/customers/${c.id}/generate-key?rotate=${rotate}`)
      setKeyInfo({ customer: c.name, ...r }); load()
    } catch (e) { setErr(e.message) }
  }

  return (
    <div>
      <div className="row" style={{ justifyContent: 'space-between', marginBottom: 6 }}>
        <h2 style={{ margin: 0 }}>CERT-In API customers</h2>
        <button className="btn accent" onClick={() => setEdit({ ...EMPTY })}>New customer</button>
      </div>
      <p className="muted" style={{ marginBottom: 12 }}>
        Customers of the CERT-In alerts data product. Their keys (prefix gec_certin_) open only
        the alerts API at api.globalexportconsultancy.com/v1/certin and nothing else.
      </p>
      {err && <div className="error">{err}</div>}
      {keyInfo && (
        <div className="notice">
          <b>API key for {keyInfo.customer} (copy now, shown once):</b>
          <div className="secret">{keyInfo.api_key}</div>
          <button className="btn sm ghost" onClick={() => setKeyInfo(null)}>Dismiss</button>
        </div>
      )}
      <div className="card tablewrap">
        <table>
          <thead><tr><th>Name</th><th>Contact</th><th>Rate limit</th><th>Keys</th><th>Active</th><th></th></tr></thead>
          <tbody>
            {items.map(c => (
              <tr key={c.id}>
                <td><b>{c.name}</b></td>
                <td className="muted">{c.contact_email || '—'}</td>
                <td>{c.rate_limit}/min</td>
                <td>{c.has_api_key ? 'primary' : 'none'}{c.has_secondary_key ? ' + old (rotation)' : ''}</td>
                <td>{c.is_active ? <span className="pill ok">yes</span> : <span className="pill bad">no</span>}</td>
                <td className="row">
                  <button className="btn sm ghost" onClick={() => setEdit(c)}>Edit</button>
                  <button className="btn sm" onClick={() => genKey(c, c.has_api_key)}>{c.has_api_key ? 'Rotate key' : 'Generate key'}</button>
                  {c.has_secondary_key && <button className="btn sm ghost" onClick={async () => { await api('POST', `/admin/api/certin/customers/${c.id}/retire-old-key`); load() }}>Retire old key</button>}
                </td>
              </tr>
            ))}
            {!items.length && <tr><td colSpan={6} className="muted">No CERT-In customers yet. Create one and generate their key.</td></tr>}
          </tbody>
        </table>
      </div>
      {edit && <Modal c0={edit} onClose={ok => { setEdit(null); if (ok) load() }} />}
    </div>
  )
}

function Modal({ c0, onClose }) {
  const [f, setF] = useState(c0)
  const [err, setErr] = useState('')
  const set = k => e => setF({ ...f, [k]: e.target.type === 'checkbox' ? e.target.checked : e.target.value })

  async function submit(e) {
    e.preventDefault(); setErr('')
    const body = { name: f.name, contact_email: f.contact_email, rate_limit: parseInt(f.rate_limit) || 120, is_active: f.is_active }
    try {
      if (c0.id) await api('PUT', `/admin/api/certin/customers/${c0.id}`, body)
      else await api('POST', '/admin/api/certin/customers', body)
      onClose(true)
    } catch (e2) { setErr(e2.message) }
  }

  return (
    <div className="modal-bg" onClick={() => onClose(false)}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <h2>{c0.id ? 'Edit customer' : 'New CERT-In customer'}</h2>
        {err && <div className="error">{err}</div>}
        <form onSubmit={submit}>
          <label>Name</label><input value={f.name} onChange={set('name')} required />
          <label>Contact email</label><input type="email" value={f.contact_email} onChange={set('contact_email')} />
          <label>Rate limit (requests per minute)</label><input type="number" min="1" value={f.rate_limit} onChange={set('rate_limit')} />
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
