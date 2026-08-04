import React, { useState } from 'react'
import { api, setToken } from '../api.js'

export default function Login({ onLogin }) {
  const [step, setStep] = useState('creds')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [pre, setPre] = useState(null)
  const [enrol, setEnrol] = useState(null)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  async function submitCreds(e) {
    e.preventDefault(); setErr(''); setBusy(true)
    try {
      const r = await api('POST', '/admin/api/auth/login', { email, password })
      setPre(r.pre_token)
      if (r.step === 'enrol_2fa') { setEnrol(r); setStep('enrol') }
      else setStep('code')
    } catch (e2) { setErr(e2.message) } finally { setBusy(false) }
  }

  async function submitCode(e) {
    e.preventDefault(); setErr(''); setBusy(true)
    try {
      const r = step === 'enrol'
        ? await api('POST', '/admin/api/auth/enrol', { pre_token: pre, totp_secret: enrol.totp_secret, code })
        : await api('POST', '/admin/api/auth/verify', { pre_token: pre, code })
      setToken(r.token)
      onLogin({ email: r.email, role: r.role, name: r.name })
    } catch (e2) { setErr(e2.message) } finally { setBusy(false) }
  }

  return (
    <div className="login-wrap">
      <div className="login-box">
        <h1>GEC Admin Console</h1>
        <p className="sub">Global Export Consultancy operations</p>
        {err && <div className="error">{err}</div>}

        {step === 'creds' && (
          <form onSubmit={submitCreds}>
            <label>Email</label>
            <input value={email} onChange={e => setEmail(e.target.value)} type="email" required autoFocus />
            <label>Password</label>
            <input value={password} onChange={e => setPassword(e.target.value)} type="password" required />
            <div style={{ marginTop: 14 }}><button className="btn accent" disabled={busy} style={{ width: '100%' }}>Continue</button></div>
          </form>
        )}

        {step === 'enrol' && (
          <form onSubmit={submitCode}>
            <div className="notice">
              First sign in: set up two factor authentication. Open Google Authenticator
              (or any authenticator app), choose <b>Enter a setup key</b>, and add the key below
              for account <b>{email}</b>.
            </div>
            <div className="secret">{enrol.totp_secret}</div>
            <label>6 digit code from the app</label>
            <input value={code} onChange={e => setCode(e.target.value)} inputMode="numeric" maxLength={6} required autoFocus />
            <div style={{ marginTop: 14 }}><button className="btn accent" disabled={busy} style={{ width: '100%' }}>Verify and sign in</button></div>
          </form>
        )}

        {step === 'code' && (
          <form onSubmit={submitCode}>
            <label>Two factor code</label>
            <input value={code} onChange={e => setCode(e.target.value)} inputMode="numeric" maxLength={6} required autoFocus />
            <div style={{ marginTop: 14 }}><button className="btn accent" disabled={busy} style={{ width: '100%' }}>Sign in</button></div>
          </form>
        )}
      </div>
    </div>
  )
}
