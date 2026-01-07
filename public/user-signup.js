document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('signup-form')
  const errorEl = document.getElementById('error-message')
  const successEl = document.getElementById('success-message')
  const btn = document.querySelector('.signup-button')

  if (!form) return

  form.addEventListener('submit', async (e) => {
    e.preventDefault()

    errorEl.style.display = 'none'
    successEl.style.display = 'none'
    errorEl.textContent = ''
    successEl.textContent = ''

    const username = document.getElementById('username')?.value.trim()
    const password = document.getElementById('password')?.value || ''

    if (!username || username.length < 3 || username.length > 32) {
      errorEl.textContent = 'Username must be 3–32 characters.'
      errorEl.style.display = 'block'
      return
    }

    if (!password || password.length < 8) {
      errorEl.textContent = 'Password must be at least 8 characters.'
      errorEl.style.display = 'block'
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

      const text = await res.text()
      let data
      try { data = JSON.parse(text) } catch { data = null }

      if (!res.ok) {
        throw new Error(
          typeof data?.error === 'string' ? data.error :
          typeof data?.message === 'string' ? data.message :
          `Signup failed (${res.status})`
        )
      }

      successEl.textContent = 'Account created. Redirecting...'
      successEl.style.display = 'block'
      setTimeout(() => { window.location.href = data?.redirect || '/image-host/' }, 900)
    } catch (err) {
      errorEl.textContent = err?.message || 'Signup failed'
      errorEl.style.display = 'block'
    } finally {
      btn.disabled = false
    }
  })
})
