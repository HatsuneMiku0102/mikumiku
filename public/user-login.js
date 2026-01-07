document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('login-form')
  const errorEl = document.getElementById('error')
  const btn = document.getElementById('login-btn')

  const setErr = (msg) => {
    errorEl.textContent = msg || ''
    errorEl.style.display = msg ? 'block' : 'none'
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault()
    setErr('')

    const username = String(document.getElementById('username').value || '').trim()
    const password = String(document.getElementById('password').value || '')

    if (!username || !password) return setErr('Enter username and password.')

    btn.disabled = true

    try {
      const res = await fetch('/user/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ username, password })
      })

      const data = await res.json().catch(() => ({}))
      if (!res.ok) return setErr(String(data.error || 'Login failed.'))

      window.location.href = data.redirect || '/image-host/'
    } catch (err) {
      setErr(err?.message || 'Login failed.')
    } finally {
      btn.disabled = false
    }
  })
})
