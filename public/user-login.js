document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('login-form')
  const errorEl = document.getElementById('error')
  const btn = document.getElementById('login-btn')
  const pass = document.getElementById('password')
  const user = document.getElementById('username')

  const togglePass = document.getElementById('togglePass') || document.querySelector('[data-toggle-pass]')
  const capsEl = document.getElementById('caps') || null

  const setErr = (msg) => {
    if (!errorEl) return
    errorEl.textContent = msg || ''
    errorEl.style.display = msg ? 'block' : 'none'
  }

  const setBusy = (busy) => {
    if (!btn) return
    btn.disabled = !!busy
    btn.textContent = busy ? 'Logging in…' : 'Log in'
  }

  const setCaps = (on) => {
    if (!capsEl) return
    capsEl.textContent = on ? 'Caps Lock is on' : ''
    capsEl.style.display = on ? 'block' : 'none'
  }

  const togglePassword = () => {
    if (!pass || !togglePass) return
    const show = pass.type === 'password'
    pass.type = show ? 'text' : 'password'
    togglePass.textContent = show ? 'Hide' : 'Show'
    togglePass.setAttribute('aria-pressed', show ? 'true' : 'false')
    togglePass.setAttribute('aria-label', show ? 'Hide password' : 'Show password')
    pass.focus()
  }

  if (togglePass) {
    togglePass.setAttribute('type', 'button')
    togglePass.setAttribute('aria-pressed', 'false')
    togglePass.addEventListener('click', (e) => {
      e.preventDefault()
      e.stopPropagation()
      togglePassword()
    })
    togglePass.addEventListener('pointerdown', (e) => {
      e.preventDefault()
    })
  }

  if (pass) {
    pass.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') setErr('')
      if (typeof e.getModifierState === 'function') setCaps(e.getModifierState('CapsLock'))
    })
    pass.addEventListener('keyup', (e) => {
      if (typeof e.getModifierState === 'function') setCaps(e.getModifierState('CapsLock'))
    })
    pass.addEventListener('blur', () => setCaps(false))
  }

  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault()
      setErr('')

      const username = String(user?.value || '').trim()
      const password = String(pass?.value || '')

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
  }
})
