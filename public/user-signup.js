document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('signup-form')
  const errorEl = document.getElementById('error')
  const okEl = document.getElementById('ok')
  const btn = document.getElementById('signup-btn')

  const show = (el, msg) => {
    if (!el) return
    el.textContent = msg || ''
    el.style.display = msg ? 'block' : 'none'
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault()
    show(errorEl, '')
    show(okEl, '')

    const username = document.getElementById('username')?.value.trim() || ''
    const password = document.getElementById('password')?.value || ''

    if (username.length < 3 || username.length > 32) {
      show(errorEl, 'Username must be 3–32 characters')
      return
    }

    if (password.length < 8) {
      show(errorEl, 'Password must be at least 8 characters')
      return
    }

    btn.disabled = true

    try {
      const res = await fetch('/user/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ username, password })
      })

      const data = await res.json()
      if (!res.ok) {
        show(errorEl, data.error || 'Signup failed')
        return
      }

      show(okEl, 'Account created. Redirecting…')
      setTimeout(() => {
        window.location.href = data.redirect || '/image-host/'
      }, 800)
    } catch {
      show(errorEl, 'Network error')
    } finally {
      btn.disabled = false
    }
  })
})
