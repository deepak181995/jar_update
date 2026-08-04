import React, { useEffect, useState } from 'react'
import { api } from '../api.js'

const EMPTY = { name: '', contact_name: '', contact_email: '', contact_phone: '', coverage_regions: '', service_rating: 0, payment_terms: '', is_active: true }

export default function Forwarders({ me }) {
  const [items, setItems] = useState([])
  const [edit, setEdit] = useState(null)
  const [err, setErr] = useState('')
  const canWrite = me.role !== 'readonly'

  async function load() { try { setItems((await api('GET', '/admin/api/forwarders')).items) } catch (e) { setErr(e.message) } }
  useEffect(() => { load() }, [])

  return (
    <div>
      <div className="row" style={{ justifyContent: 'space-between', marginBottom: 12 }}>
        <h2 style={{ margin: 0 }}>Forwarder panel <span className="muted">(internal, never exposed to partners)</span></h2>
        {canWrite && <button className="btn accent" onClick={() => setEdit({ ...EMPTY })}>New forwarder</button>}
      </div>
      {err && <div className="error">{err}</div>}
      <div className="card tablewrap">
        <table>
          <thead><tr><th>Name</th><th>Contact</th><th>Coverage</th><th>Rating</th><th>Payment terms</th><th>Active</th><th></th></tr></thead>
          <tbody>
            {items.map(x => (
              <tr key={x.id}>
                <td><b>{x.name}</b></td>
                <td>{x.contact_name}<div className="muted">{x.contact_email} {x.contact_phone}</div></td>
                <td>{x.coverage_regions}</td>
                <td>{x.service_rating || '—'}</td>
                <td>{x.payment_terms}</td>
                <td>{x.is_active ? <span className="pill ok">yes</span> : <span className="pill bad">no</span>}</td>
                <td>{canWrite && <button className="btn sm ghost" onClick={() => setEdit(x)}>Edit</button>}</td>
              </tr>
            ))}
            {!items.length && <tr><td colSpan={7} className="muted">No forwarders yet.</td></tr>}
          </tbody>
        </table>
      </div>
      {edit && <Modal f0={edit} onClose={ok => { setEdit(null); if (ok) load() }} />}
    </div>
  )
}

function Modal({ f0, onClose }) {
  const [f, setF] = useState(f0)
  const [err, setErr] = useState('')
  const set = k => e => setF({ ...f, [k]: e.target.type === 'checkbox' ? e.target.checked : e.target.value })

  async function submit(e) {
    e.preventDefault(); setErr('')
    const body = { ...f, service_rating: parseFloat(f.service_rating) || 0 }
    delete body.id; delete body.created_at
    try {
      if (f0.id) await api('PUT', `/admin/api/forwarders/${f0.id}`, body)
      else await api('POST', '/admin/api/forwarders', body)
      onClose(true)
    } catch (e2) { setErr(e2.message) }
  }

  return (
    <div className="modal-bg" onClick={() => onClose(false)}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <h2>{f0.id ? 'Edit forwarder' : 'New forwarder'}</h2>
        {err && <div className="error">{err}</div>}
        <form onSubmit={submit}>
          <div className="grid g2">
            <div><label>Name</label><input value={f.name} onChange={set('name')} required /></div>
            <div><label>Contact name</label><input value={f.contact_name} onChange={set('contact_name')} /></div>
            <div><label>Contact email</label><input type="email" value={f.contact_email} onChange={set('contact_email')} /></div>
            <div><label>Contact phone</label><input value={f.contact_phone} onChange={set('contact_phone')} /></div>
            <div><label>Coverage regions</label><input value={f.coverage_regions} onChange={set('coverage_regions')} placeholder="Africa, Gulf, Europe" /></div>
            <div><label>Service rating (0 to 5)</label><input type="number" step="0.1" min="0" max="5" value={f.service_rating} onChange={set('service_rating')} /></div>
            <div><label>Payment terms</label><input value={f.payment_terms} onChange={set('payment_terms')} placeholder="30 days credit" /></div>
          </div>
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
