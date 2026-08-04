import React, { useEffect, useRef, useState } from 'react'
import { api } from '../api.js'

const EMPTY = {
  origin_port: '', origin_country: 'India', destination_port: '', destination_country: '',
  mode: 'sea_fcl', weight_min: 0, weight_max: 0, volume_min: 0, volume_max: 0,
  incoterm: 'CIF', forwarder_id: '', buy_rate: '', buy_currency: 'USD',
  margin_type: 'percentage', margin_value: '', sell_currency: 'USD',
  transit_days: '', valid_from: '', valid_until: '', surcharge_notes: '', is_active: true,
}

export default function Rates({ me }) {
  const [items, setItems] = useState([])
  const [total, setTotal] = useState(0)
  const [q, setQ] = useState('')
  const [expiring, setExpiring] = useState(false)
  const [edit, setEdit] = useState(null)
  const [err, setErr] = useState('')
  const [csvResult, setCsvResult] = useState(null)
  const fileRef = useRef()
  const canWrite = me.role !== 'readonly'

  async function load() {
    try {
      const r = await api('GET', `/admin/api/rates?q=${encodeURIComponent(q)}${expiring ? '&expiring_days=7' : ''}`)
      setItems(r.items); setTotal(r.total)
    } catch (e) { setErr(e.message) }
  }
  useEffect(() => { load() }, [q, expiring])

  async function uploadCsv(e) {
    const file = e.target.files[0]
    if (!file) return
    const fd = new FormData(); fd.append('file', file)
    try {
      setCsvResult(await api('POST', '/admin/api/rates/upload-csv', fd, true))
      load()
    } catch (e2) { setErr(e2.message) }
    fileRef.current.value = ''
  }

  return (
    <div>
      <div className="row" style={{ justifyContent: 'space-between', marginBottom: 12 }}>
        <h2 style={{ margin: 0 }}>Rate management <span className="muted">({total})</span></h2>
        {canWrite && (
          <div className="row">
            <button className="btn ghost" onClick={() => fileRef.current.click()}>Upload CSV</button>
            <input ref={fileRef} type="file" accept=".csv" style={{ display: 'none' }} onChange={uploadCsv} />
            <button className="btn accent" onClick={() => setEdit({ ...EMPTY })}>New rate</button>
          </div>
        )}
      </div>
      {err && <div className="error">{err}</div>}
      {csvResult && (
        <div className="notice">
          CSV upload: {csvResult.created} rates created, {csvResult.errors.length} errors.
          {csvResult.errors.slice(0, 5).map((e, i) => <div key={i}>Line {e.line}: {e.error}</div>)}
          <div className="muted">Columns: {csvResult.template_columns.join(', ')}</div>
        </div>
      )}
      <div className="card">
        <div className="row" style={{ marginBottom: 10 }}>
          <input placeholder="Search port or country" value={q} onChange={e => setQ(e.target.value)} style={{ maxWidth: 280 }} />
          <label style={{ margin: 0 }}><input type="checkbox" checked={expiring} onChange={e => setExpiring(e.target.checked)} style={{ width: 'auto', marginRight: 6 }} />Expiring within 7 days</label>
        </div>
        <div className="tablewrap">
          <table>
            <thead><tr><th>Route</th><th>Mode</th><th>Buy</th><th>Margin</th><th>Sell</th><th>Transit</th><th>Valid until</th><th>Active</th><th></th></tr></thead>
            <tbody>
              {items.map(r => (
                <tr key={r.id} style={{ opacity: r.is_active ? 1 : .5 }}>
                  <td>{r.origin_port} → {r.destination_port}, {r.destination_country}</td>
                  <td>{r.mode}</td>
                  <td>{r.buy_rate} {r.buy_currency}</td>
                  <td>{r.margin_type === 'fixed' ? `+${r.margin_value}` : `${r.margin_value}%`}</td>
                  <td><b>{r.sell_rate} {r.sell_currency}</b></td>
                  <td>{r.transit_days}d</td>
                  <td className="muted">{r.valid_until ? new Date(r.valid_until).toLocaleDateString() : '—'}</td>
                  <td>{r.is_active ? <span className="pill ok">yes</span> : <span className="pill bad">no</span>}</td>
                  <td>{canWrite && <button className="btn sm ghost" onClick={() => setEdit({ ...r, valid_from: r.valid_from?.slice(0, 10) || '', valid_until: r.valid_until?.slice(0, 10) || '', forwarder_id: r.forwarder_id || '' })}>Edit</button>}</td>
                </tr>
              ))}
              {!items.length && <tr><td colSpan={9} className="muted">No rates found.</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
      {edit && <RateModal rate={edit} onClose={ok => { setEdit(null); if (ok) load() }} />}
    </div>
  )
}

function RateModal({ rate, onClose }) {
  const [f, setF] = useState(rate)
  const [forwarders, setForwarders] = useState([])
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(() => { api('GET', '/admin/api/forwarders').then(r => setForwarders(r.items)).catch(() => {}) }, [])
  const set = k => e => setF({ ...f, [k]: e.target.type === 'checkbox' ? e.target.checked : e.target.value })

  const buy = parseFloat(f.buy_rate) || 0
  const mv = parseFloat(f.margin_value) || 0
  const sell = f.margin_type === 'fixed' ? buy + mv : buy * (1 + mv / 100)

  async function submit(e) {
    e.preventDefault(); setErr(''); setBusy(true)
    const body = {
      ...f,
      forwarder_id: f.forwarder_id ? parseInt(f.forwarder_id) : null,
      weight_min: parseFloat(f.weight_min) || 0, weight_max: parseFloat(f.weight_max) || 0,
      volume_min: parseFloat(f.volume_min) || 0, volume_max: parseFloat(f.volume_max) || 0,
      buy_rate: buy, margin_value: mv, transit_days: parseInt(f.transit_days) || 0,
      valid_from: f.valid_from ? f.valid_from + 'T00:00:00+00:00' : null,
      valid_until: f.valid_until ? f.valid_until + 'T23:59:59+00:00' : null,
    }
    delete body.id; delete body.sell_rate; delete body.created_at
    try {
      if (rate.id) await api('PUT', `/admin/api/rates/${rate.id}`, body)
      else await api('POST', '/admin/api/rates', body)
      onClose(true)
    } catch (e2) { setErr(e2.message); setBusy(false) }
  }

  return (
    <div className="modal-bg" onClick={() => onClose(false)}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <h2>{rate.id ? 'Edit rate' : 'New rate'}</h2>
        {err && <div className="error">{err}</div>}
        <form onSubmit={submit}>
          <div className="grid g2">
            <div><label>Origin port</label><input value={f.origin_port} onChange={set('origin_port')} required /></div>
            <div><label>Origin country</label><input value={f.origin_country} onChange={set('origin_country')} required /></div>
            <div><label>Destination port</label><input value={f.destination_port} onChange={set('destination_port')} required /></div>
            <div><label>Destination country</label><input value={f.destination_country} onChange={set('destination_country')} required /></div>
            <div>
              <label>Mode</label>
              <select value={f.mode} onChange={set('mode')}>
                <option value="air">Air</option><option value="sea_fcl">Sea FCL</option>
                <option value="sea_lcl">Sea LCL</option><option value="multimodal">Multimodal</option>
              </select>
            </div>
            <div><label>Incoterm</label><input value={f.incoterm} onChange={set('incoterm')} maxLength={8} /></div>
            <div>
              <label>Forwarder (internal)</label>
              <select value={f.forwarder_id} onChange={set('forwarder_id')}>
                <option value="">None</option>
                {forwarders.map(x => <option key={x.id} value={x.id}>{x.name}</option>)}
              </select>
            </div>
            <div><label>Transit days</label><input type="number" min="0" value={f.transit_days} onChange={set('transit_days')} /></div>
            <div><label>Buy rate</label><input type="number" step="0.01" min="0" value={f.buy_rate} onChange={set('buy_rate')} required /></div>
            <div><label>Buy currency</label><input value={f.buy_currency} onChange={set('buy_currency')} maxLength={8} /></div>
            <div>
              <label>Margin type</label>
              <select value={f.margin_type} onChange={set('margin_type')}>
                <option value="percentage">Percentage</option><option value="fixed">Fixed amount</option>
              </select>
            </div>
            <div><label>Margin value</label><input type="number" step="0.01" min="0" value={f.margin_value} onChange={set('margin_value')} required /></div>
            <div><label>Valid from</label><input type="date" value={f.valid_from} onChange={set('valid_from')} /></div>
            <div><label>Valid until</label><input type="date" value={f.valid_until} onChange={set('valid_until')} /></div>
            <div><label>Weight range (kg)</label><div className="row"><input type="number" value={f.weight_min} onChange={set('weight_min')} /><input type="number" value={f.weight_max} onChange={set('weight_max')} /></div></div>
            <div><label>Volume range (cbm)</label><div className="row"><input type="number" value={f.volume_min} onChange={set('volume_min')} /><input type="number" value={f.volume_max} onChange={set('volume_max')} /></div></div>
          </div>
          <label>Surcharge notes</label>
          <textarea rows={2} value={f.surcharge_notes} onChange={set('surcharge_notes')} />
          <div className="row" style={{ marginTop: 10 }}>
            <label style={{ margin: 0 }}><input type="checkbox" checked={f.is_active} onChange={set('is_active')} style={{ width: 'auto', marginRight: 6 }} />Active</label>
          </div>
          <div className="row" style={{ marginTop: 14, justifyContent: 'space-between' }}>
            <div>Sell rate: <b>{sell ? sell.toFixed(2) : '—'} {f.sell_currency}</b></div>
            <div className="row">
              <button type="button" className="btn ghost" onClick={() => onClose(false)}>Cancel</button>
              <button className="btn accent" disabled={busy}>Save</button>
            </div>
          </div>
        </form>
      </div>
    </div>
  )
}
