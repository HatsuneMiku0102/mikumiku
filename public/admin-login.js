document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('login-form')
  const errorEl = document.getElementById('error-message')
  const successEl = document.getElementById('success-message')
  const spinner = document.getElementById('loading-spinner')
  const button = document.querySelector('.login-button')

  if (!form) return

  form.addEventListener('submit', async (e) => {
    e.preventDefault()

    errorEl.style.display = 'none'
    successEl.style.display = 'none'
    errorEl.textContent = ''
    successEl.textContent = ''

    const username = document.getElementById('username')?.value.trim()
    const password = document.getElementById('password')?.value.trim()
    const isAdmin = form.dataset.role === 'admin'

    if (!username || !password) {
      errorEl.textContent = 'Please enter both username and password.'
      errorEl.style.display = 'block'
      return
    }

    button.disabled = true
    if (spinner) spinner.style.display = 'block'

    try {
      const res = await fetch(isAdmin ? '/login' : '/user/login', {
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
          `Login failed (${res.status})`
        )
      }

      successEl.textContent = 'Login successful. Redirecting...'
      successEl.style.display = 'block'

      setTimeout(() => {
        window.location.href = data?.redirect || '/'
      }, 900)

    } catch (err) {
      errorEl.textContent = err?.message || 'Login failed'
      errorEl.style.display = 'block'
    } finally {
      button.disabled = false
      if (spinner) spinner.style.display = 'none'
    }
  })
})
