import React, { useEffect, useState } from 'react'
import { api } from '../api.js'

const EMPTY = { email: '', name: '', role: 'operations', password: '', is_active: true }

export default function Users() {
  const [items, setItems] = useState([])
  const [edit, setEdit] = useState(null)
  const [err, setErr] = useState('')

  async function load() { try { setItems((await api('GET', '/admin/api/users')).items) } catch (e) { setErr(e.message) } }
  useEffect(() => { load() }, [])

  return (
    <div>
      <div className="row" style={{ justifyContent: 'space-between', marginBottom: 12 }}>
        <h2 style={{ margin: 0 }}>Console users</h2>
        <button className="btn accent" onClick={() => setEdit({ ...EMPTY })}>New user</button>
      </div>
      {err && <div className="error">{err}</div>}
      <div className="card tablewrap">
        <table>
          <thead><tr><th>Email</th><th>Name</th><th>Role</th><th>2FA</th><th>Active</th><th></th></tr></thead>
          <tbody>
            {items.map(u => (
              <tr key={u.id}>
                <td>{u.email}</td><td>{u.name}</td><td>{u.role}</td>
                <td>{u.has_2fa ? <span className="pill ok">enrolled</span> : <span className="pill PENDING">pending</span>}</td>
                <td>{u.is_active ? <span className="pill ok">yes</span> : <span className="pill bad">no</span>}</td>
                <td><button className="btn sm ghost" onClick={() => setEdit({ ...u, password: '' })}>Edit</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {edit && <Modal u0={edit} onClose={ok => { setEdit(null); if (ok) load() }} />}
    </div>
  )
}

function Modal({ u0, onClose }) {
  const [f, setF] = useState(u0)
  const [err, setErr] = useState('')
  const set = k => e => setF({ ...f, [k]: e.target.type === 'checkbox' ? e.target.checked : e.target.value })

  async function submit(e) {
    e.preventDefault(); setErr('')
    const body = { email: f.email, name: f.name, role: f.role, is_active: f.is_active, password: f.password || null }
    try {
      if (u0.id) await api('PUT', `/admin/api/users/${u0.id}`, body)
      else await api('POST', '/admin/api/users', body)
      onClose(true)
    } catch (e2) { setErr(e2.message) }
  }

  return (
    <div className="modal-bg" onClick={() => onClose(false)}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <h2>{u0.id ? 'Edit user' : 'New user'}</h2>
        {err && <div className="error">{err}</div>}
        <form onSubmit={submit}>
          <label>Email</label><input type="email" value={f.email} onChange={set('email')} required disabled={!!u0.id} />
          <label>Name</label><input value={f.name} onChange={set('name')} />
          <label>Role</label>
          <select value={f.role} onChange={set('role')}>
            <option value="administrator">Administrator</option>
            <option value="operations">Operations executive</option>
            <option value="readonly">Read only</option>
          </select>
          <label>{u0.id ? 'Reset password (leave blank to keep, resets 2FA)' : 'Password (minimum 10 characters)'}</label>
          <input type="password" value={f.password} onChange={set('password')} minLength={u0.id && !f.password ? 0 : 10} />
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
