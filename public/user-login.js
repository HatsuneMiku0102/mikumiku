document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('login-form')
  const errorEl = document.getElementById('error')
  const btn = document.getElementById('login-btn')
  const togglePass = document.getElementById('togglePass')
  const pass = document.getElementById('password')
  const user = document.getElementById('username')

  const setErr = (msg) => {
    errorEl.textContent = msg || ''
    errorEl.style.display = msg ? 'block' : 'none'
  }

  const setBusy = (busy) => {
    btn.disabled = !!busy
    btn.textContent = busy ? 'Logging in…' : 'Log in'
  }

  if (togglePass && pass) {
    togglePass.addEventListener('click', () => {
      const show = pass.type === 'password'
      pass.type = show ? 'text' : 'password'
      togglePass.textContent = show ? 'Hide' : 'Show'
    })
  }

  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') setErr('')
  })

  form.addEventListener('submit', async (e) => {
    e.preventDefault()
    setErr('')

    const username = String(user.value || '').trim()
    const password = String(pass.value || '')

    if (!username || !password) return setErr('Enter username and password.')

    setBusy(true)

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
      setBusy(false)
    }
  })
})
