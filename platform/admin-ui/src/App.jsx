import React, { useEffect, useState } from 'react'
import { api, getToken, setToken } from './api.js'
import Login from './screens/Login.jsx'
import Dashboard from './screens/Dashboard.jsx'
import Quotes from './screens/Quotes.jsx'
import Rates from './screens/Rates.jsx'
import Forwarders from './screens/Forwarders.jsx'
import Partners from './screens/Partners.jsx'
import Users from './screens/Users.jsx'
import Reports from './screens/Reports.jsx'
import Audit from './screens/Audit.jsx'

const TABS = [
  { id: 'dashboard', label: 'Dashboard', roles: ['administrator', 'operations', 'readonly'], C: Dashboard },
  { id: 'quotes', label: 'Quotes', roles: ['administrator', 'operations', 'readonly'], C: Quotes },
  { id: 'rates', label: 'Rates', roles: ['administrator', 'operations', 'readonly'], C: Rates },
  { id: 'forwarders', label: 'Forwarders', roles: ['administrator', 'operations', 'readonly'], C: Forwarders },
  { id: 'partners', label: 'Partners', roles: ['administrator'], C: Partners },
  { id: 'users', label: 'Users', roles: ['administrator'], C: Users },
  { id: 'reports', label: 'Reports', roles: ['administrator', 'operations', 'readonly'], C: Reports },
  { id: 'audit', label: 'Audit Log', roles: ['administrator'], C: Audit },
]

export default function App() {
  const [me, setMe] = useState(null)
  const [tab, setTab] = useState('dashboard')
  const [checking, setChecking] = useState(!!getToken())

  useEffect(() => {
    const onLogout = () => setMe(null)
    window.addEventListener('gec-logout', onLogout)
    if (getToken()) {
      api('GET', '/admin/api/auth/me')
        .then(setMe).catch(() => setToken(null))
        .finally(() => setChecking(false))
    }
    return () => window.removeEventListener('gec-logout', onLogout)
  }, [])

  if (checking) return null
  if (!me) return <Login onLogin={setMe} />

  const visible = TABS.filter(t => t.roles.includes(me.role))
  const Active = (visible.find(t => t.id === tab) || visible[0]).C

  return (
    <div>
      <div className="topbar">
        <div className="brand">GEC Admin<small>Global Export Consultancy</small></div>
        <nav>
          {visible.map(t => (
            <button key={t.id} className={tab === t.id ? 'active' : ''} onClick={() => setTab(t.id)}>{t.label}</button>
          ))}
        </nav>
        <div className="spacer" />
        <div className="who">{me.email} · {me.role}</div>
        <button className="logout" onClick={() => { setToken(null); setMe(null) }}>Sign out</button>
      </div>
      <div className="page"><Active me={me} /></div>
    </div>
  )
}
