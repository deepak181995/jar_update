import React, { useEffect, useState } from 'react'
import { api } from '../api.js'

export function QuoteEntryModal({ request, onClose }) {
  const [f, setF] = useState({
    forwarder_id: '', buy_rate: '', buy_currency: 'USD', margin_type: 'percentage',
    margin_value: '', sell_currency: 'USD', transit_days: '', validity_days: 14,
    surcharge_notes: '', save_to_rates: true,
  })
  const [forwarders, setForwarders] = useState([])
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(() => { api('GET', '/admin/api/forwarders').then(r => setForwarders(r.items)).catch(() => {}) }, [])

  const buy = parseFloat(f.buy_rate) || 0
  const mv = parseFloat(f.margin_value) || 0
  const sell = f.margin_type === 'fixed' ? buy + mv : buy * (1 + mv / 100)

  async function submit(e) {
    e.preventDefault(); setErr(''); setBusy(true)
    try {
      await api('POST', `/admin/api/quotes/${request.id}/quote`, {
        forwarder_id: f.forwarder_id ? parseInt(f.forwarder_id) : null,
        buy_rate: buy, buy_currency: f.buy_currency,
        margin_type: f.margin_type, margin_value: mv,
        sell_currency: f.sell_currency, transit_days: parseInt(f.transit_days) || 0,
        validity_days: parseInt(f.validity_days) || 14,
        charge_breakdown: [], surcharge_notes: f.surcharge_notes,
        save_to_rates: f.save_to_rates,
      })
      onClose(true)
    } catch (e2) { setErr(e2.message); setBusy(false) }
  }

  const set = k => e => setF({ ...f, [k]: e.target.type === 'checkbox' ? e.target.checked : e.target.value })

  return (
    <div className="modal-bg" onClick={() => onClose(false)}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <h2>Quote {request.reference_number}</h2>
        <p className="muted">{request.origin_port} → {request.destination_port}, {request.destination_country} · {request.mode} · {request.cargo_description?.slice(0, 80)}</p>
        {err && <div className="error">{err}</div>}
        <form onSubmit={submit}>
          <div className="grid g2">
            <div>
              <label>Forwarder (internal)</label>
              <select value={f.forwarder_id} onChange={set('forwarder_id')}>
                <option value="">Select forwarder</option>
                {forwarders.map(x => <option key={x.id} value={x.id}>{x.name}</option>)}
              </select>
            </div>
            <div><label>Buy rate</label><input type="number" step="0.01" min="0" value={f.buy_rate} onChange={set('buy_rate')} required /></div>
            <div><label>Buy currency</label><input value={f.buy_currency} onChange={set('buy_currency')} maxLength={8} /></div>
            <div>
              <label>Margin type</label>
              <select value={f.margin_type} onChange={set('margin_type')}>
                <option value="percentage">Percentage</option>
                <option value="fixed">Fixed amount</option>
              </select>
            </div>
            <div><label>Margin value</label><input type="number" step="0.01" min="0" value={f.margin_value} onChange={set('margin_value')} required /></div>
            <div><label>Sell currency</label><input value={f.sell_currency} onChange={set('sell_currency')} maxLength={8} /></div>
            <div><label>Transit days</label><input type="number" min="0" value={f.transit_days} onChange={set('transit_days')} required /></div>
            <div><label>Validity (days)</label><input type="number" min="1" max="90" value={f.validity_days} onChange={set('validity_days')} /></div>
          </div>
          <label>Surcharge notes (shown to partner)</label>
          <textarea rows={2} value={f.surcharge_notes} onChange={set('surcharge_notes')} />
          <div className="row" style={{ marginTop: 10 }}>
            <label style={{ margin: 0 }}><input type="checkbox" checked={f.save_to_rates} onChange={set('save_to_rates')} style={{ width: 'auto', marginRight: 6 }} />Save as reusable rate</label>
          </div>
          <div className="row" style={{ marginTop: 14, justifyContent: 'space-between' }}>
            <div>Sell rate: <b>{sell ? sell.toFixed(2) : '—'} {f.sell_currency}</b></div>
            <div className="row">
              <button type="button" className="btn ghost" onClick={() => onClose(false)}>Cancel</button>
              <button className="btn accent" disabled={busy}>Issue quote</button>
            </div>
          </div>
        </form>
      </div>
    </div>
  )
}

export default function Quotes({ me }) {
  const [items, setItems] = useState([])
  const [showNew, setShowNew] = useState(false)
  const [entry, setEntry] = useState(null)
  const [err, setErr] = useState('')
  const canWrite = me.role !== 'readonly'

  async function load() {
    try { setItems((await api('GET', '/admin/api/quotes')).items) } catch (e) { setErr(e.message) }
  }
  useEffect(() => { load() }, [])

  return (
    <div>
      <div className="row" style={{ justifyContent: 'space-between', marginBottom: 12 }}>
        <h2 style={{ margin: 0 }}>Quote requests</h2>
        {canWrite && <button className="btn accent" onClick={() => setShowNew(true)}>New request</button>}
      </div>
      {err && <div className="error">{err}</div>}
      <div className="card tablewrap">
        <table>
          <thead><tr><th>Reference</th><th>Source</th><th>Route</th><th>Mode</th><th>Status</th><th>Quote</th><th>Created</th><th></th></tr></thead>
          <tbody>
            {items.map(q => (
              <tr key={q.id}>
                <td>{q.reference_number}</td>
                <td>{q.partner_name || 'Manual'}</td>
                <td>{q.origin_port} → {q.destination_port}, {q.destination_country}</td>
                <td>{q.mode}</td>
                <td><span className={'pill ' + q.status}>{q.status}</span></td>
                <td>{q.quote ? `${q.quote.sell_rate} ${q.quote.currency} · ${q.quote.transit_days}d` : '—'}</td>
                <td className="muted">{new Date(q.created_at).toLocaleString()}</td>
                <td>{canWrite && q.status === 'PENDING' && <button className="btn sm accent" onClick={() => setEntry(q)}>Enter quote</button>}</td>
              </tr>
            ))}
            {!items.length && <tr><td colSpan={8} className="muted">No quote requests yet.</td></tr>}
          </tbody>
        </table>
      </div>
      {showNew && <NewRequestModal onClose={ok => { setShowNew(false); if (ok) load() }} />}
      {entry && <QuoteEntryModal request={entry} onClose={ok => { setEntry(null); if (ok) load() }} />}
    </div>
  )
}

function NewRequestModal({ onClose }) {
  const [f, setF] = useState({
    origin_port: '', origin_country: 'India', destination_port: '', destination_country: '',
    mode: 'sea_fcl', weight_kg: '', volume_cbm: '', cargo_description: '', hs_code: '',
    incoterm: 'CIF', ready_date: '', sla_tier: 'standard_4h',
  })
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const set = k => e => setF({ ...f, [k]: e.target.value })

  async function submit(e) {
    e.preventDefault(); setErr(''); setBusy(true)
    try {
      await api('POST', '/admin/api/quotes', {
        ...f, weight_kg: parseFloat(f.weight_kg) || 0, volume_cbm: parseFloat(f.volume_cbm) || 0,
      })
      onClose(true)
    } catch (e2) { setErr(e2.message); setBusy(false) }
  }

  return (
    <div className="modal-bg" onClick={() => onClose(false)}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <h2>New quote request</h2>
        {err && <div className="error">{err}</div>}
        <form onSubmit={submit}>
          <div className="grid g2">
            <div><label>Origin port</label><input value={f.origin_port} onChange={set('origin_port')} required /></div>
            <div><label>Origin country</label><input value={f.origin_country} onChange={set('origin_country')} /></div>
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
            <div><label>Weight (kg)</label><input type="number" step="0.1" min="0" value={f.weight_kg} onChange={set('weight_kg')} /></div>
            <div><label>Volume (cbm)</label><input type="number" step="0.01" min="0" value={f.volume_cbm} onChange={set('volume_cbm')} /></div>
            <div><label>HS code</label><input value={f.hs_code} onChange={set('hs_code')} maxLength={16} /></div>
            <div><label>Ready date</label><input type="date" value={f.ready_date} onChange={set('ready_date')} /></div>
            <div>
              <label>SLA tier</label>
              <select value={f.sla_tier} onChange={set('sla_tier')}>
                <option value="standard_4h">Known destination, unusual cargo (4 working hours)</option>
                <option value="new_destination_24h">New destination (24 working hours)</option>
                <option value="project_cargo_48h">Project, oversized or hazardous (48 working hours)</option>
                <option value="immediate">Immediate (rated route)</option>
              </select>
            </div>
          </div>
          <label>Cargo description</label>
          <textarea rows={2} value={f.cargo_description} onChange={set('cargo_description')} />
          <div className="row" style={{ marginTop: 14, justifyContent: 'flex-end' }}>
            <button type="button" className="btn ghost" onClick={() => onClose(false)}>Cancel</button>
            <button className="btn accent" disabled={busy}>Create request</button>
          </div>
        </form>
      </div>
    </div>
  )
}
