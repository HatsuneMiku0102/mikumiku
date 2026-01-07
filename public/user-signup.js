document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('signup-form')
  const errorEl = document.getElementById('error')
  const okEl = document.getElementById('ok')
  const btn = document.getElementById('signup-btn')

  const setErr = (msg) => {
    okEl.style.display = 'none'
    okEl.textContent = ''
    errorEl.textContent = msg || ''
    errorEl.style.display = msg ? 'block' : 'none'
  }

  const setOk = (msg) => {
    errorEl.style.display = 'none'
    errorEl.textContent = ''
    okEl.textContent = msg || ''
    okEl.style.display = msg ? 'block' : 'none'
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault()
    setErr('')
    setOk('')

    const username = String(document.getElementById('username').value || '').trim()
    const password = String(document.getElementById('password').value || '')

    if (username.length < 3 || username.length > 32) return setErr('Username must be 3–32 characters.')
    if (password.length < 8) return setErr('Password must be at least 8 characters.')

    btn.disabled = true

    try {
      const res = await fetch('/user/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ username, password })
      })

      const data = await res.json().catch(() => ({}))
      if (!res.ok) return setErr(String(data.error || 'Signup failed.'))

      setOk('Account created. Redirecting...')
      setTimeout(() => {
        window.location.href = data.redirect || '/image-host/'
      }, 700)
    } catch (err) {
      setErr(err?.message || 'Signup failed.')
    } finally {
      btn.disabled = false
    }
  })
})
