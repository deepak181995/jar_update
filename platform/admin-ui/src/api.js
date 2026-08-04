let token = sessionStorage.getItem('gec_token') || null
let refreshTimer = null

export function setToken(t) {
  token = t
  if (t) sessionStorage.setItem('gec_token', t)
  else sessionStorage.removeItem('gec_token')
  scheduleRefresh()
}

export function getToken() { return token }

function scheduleRefresh() {
  clearInterval(refreshTimer)
  if (token) {
    // Sliding 30 minute session: refresh every 10 minutes while active.
    refreshTimer = setInterval(async () => {
      try {
        const r = await api('POST', '/admin/api/auth/refresh')
        if (r.token) setToken(r.token)
      } catch { /* session expired; next call will redirect to login */ }
    }, 10 * 60 * 1000)
  }
}

export async function api(method, path, body, isForm) {
  const headers = {}
  if (token) headers['Authorization'] = 'Bearer ' + token
  if (body && !isForm) headers['Content-Type'] = 'application/json'
  const res = await fetch(path, {
    method,
    headers,
    body: body ? (isForm ? body : JSON.stringify(body)) : undefined,
  })
  if (res.status === 401 && token && !path.includes('/auth/')) {
    setToken(null)
    window.dispatchEvent(new Event('gec-logout'))
    throw new Error('Session expired. Please sign in again.')
  }
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(data.detail ? (typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail)) : 'Request failed')
  return data
}

scheduleRefresh()
