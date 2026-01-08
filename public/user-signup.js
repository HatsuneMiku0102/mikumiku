document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('signup-form')
  const errorEl = document.getElementById('error')
  const okEl = document.getElementById('ok')
  const btn = document.getElementById('signup-btn')
  const togglePass = document.getElementById('togglePass')
  const pass = document.getElementById('password')
  const user = document.getElementById('username')

  const show = (el, msg) => {
    el.textContent = msg || ''
    el.style.display = msg ? 'block' : 'none'
  }

  const setBusy = (busy) => {
    btn.disabled = !!busy
    btn.textContent = busy ? 'Creating…' : 'Create account'
  }

  if (togglePass && pass) {
    togglePass.addEventListener('click', () => {
      const showPass = pass.type === 'password'
      pass.type = showPass ? 'text' : 'password'
      togglePass.textContent = showPass ? 'Hide' : 'Show'
    })
  }

  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      show(errorEl, '')
      show(okEl, '')
    }
  })

  form.addEventListener('submit', async (e) => {
    e.preventDefault()
    show(errorEl, '')
    show(okEl, '')

    const username = String(user.value || '').trim()
    const password = String(pass.value || '')

    if (username.length < 3 || username.length > 32) {
      show(errorEl, 'Username must be 3–32 characters.')
      return
    }

    if (password.length < 8) {
      show(errorEl, 'Password must be at least 8 characters.')
      return
    }

    setBusy(true)

    try {
      const res = await fetch('/user/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ username, password })
      })

      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        show(errorEl, data.error || 'Signup failed.')
        return
      }

      show(okEl, 'Account created. Redirecting…')
      setTimeout(() => {
        window.location.href = data.redirect || '/image-host/'
      }, 700)
    } catch {
      show(errorEl, 'Network error.')
    } finally {
      setBusy(false)
    }
  })
})
