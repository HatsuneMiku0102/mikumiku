document.addEventListener('DOMContentLoaded', () => {
  const token = document.cookie.split('; ').find(v => v.startsWith('token='))?.split('=')[1]
  if (!token) {
    window.location.href = '/auth'
    return
  }

  const socket = io({ query: { connectionType: 'admin' } })

  const usersCountEl = document.getElementById('active-users-count')
  const usersListEl = document.getElementById('active-ip-list')
  const logoutBtn = document.getElementById('logout')
  const toggleEl = document.getElementById('lfgToggle')

  const timelineContainer = document.getElementById('minuteTimeline')
  const MAX_MINUTES = 60
  let timelineData = []

  const keyNameEl = document.getElementById('keyName')
  const keyRateEl = document.getElementById('keyRate')
  const keyScopesEl = document.getElementById('keyScopes')
  const keyNeverEl = document.getElementById('keyNeverExpires')
  const genBtn = document.getElementById('generateKeyBtn')
  const keyStatus = document.getElementById('keyStatus')
  const generatedKey = document.getElementById('generatedKey')
  const curlUpload = document.getElementById('curlUpload')
  const curlFetch = document.getElementById('curlFetch')

  function setKeyStatus(txt) {
    keyStatus.textContent = txt || ''
  }

  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-copy]')
    if (!btn) return
    const id = btn.getAttribute('data-copy')
    const el = document.getElementById(id)
    if (!el) return
    const val = el.value || el.textContent || ''
    try {
      await navigator.clipboard.writeText(val)
      const prev = btn.innerHTML
      btn.innerHTML = '<i class="fa-solid fa-check"></i> Copied'
      setTimeout(() => { btn.innerHTML = prev }, 900)
    } catch {
      const prev = btn.innerHTML
      btn.innerHTML = '<i class="fa-solid fa-xmark"></i> Failed'
      setTimeout(() => { btn.innerHTML = prev }, 900)
    }
  })

  const ctx = document.getElementById('locationChart').getContext('2d')
  const locationChart = new Chart(ctx, {
    type: 'bar',
    data: { labels: [], datasets: [{ label: 'Visitors by Country', data: [] }] },
    options: { responsive: true, scales: { y: { beginAtZero: true } } }
  })

  function updateChart(countryData) {
    const countries = (countryData || []).map(i => i._id || 'Unknown')
    const counts = (countryData || []).map(i => i.count || 0)
    locationChart.data.labels = countries
    locationChart.data.datasets[0].data = counts
    locationChart.update()
  }

  fetch('/api/geo-data').then(r => r.json()).then(updateChart).catch(() => {})
  socket.on('geoDataUpdate', updateChart)

  socket.on('connect', () => {
    socket.emit('getToggleState')
  })

  socket.on('toggleState', (data) => {
    toggleEl.checked = !!data.commands_enabled
  })

  socket.on('toggleUpdated', (data) => {
    toggleEl.checked = !!data.commands_enabled
  })

  toggleEl.addEventListener('change', () => {
    socket.emit('toggleCommands', { commands_enabled: toggleEl.checked })
  })

  function renderUsers(users) {
    usersCountEl.textContent = String(users.length)
    usersListEl.innerHTML = ''
    users.forEach(user => {
      const li = document.createElement('li')
      li.className = 'item'

      const top = document.createElement('div')
      top.className = 'itemTop'

      const left = document.createElement('div')
      const title = document.createElement('div')
      title.className = 'itemTitle'
      title.textContent = `IP: ${user.ip || 'Unknown'}`
      const meta = document.createElement('div')
      meta.className = 'itemMeta'
      const types = Array.isArray(user.connectionTypes) ? user.connectionTypes.join(', ') : String(user.connectionTypes || '')
      meta.textContent = `Connection Types: ${types || 'unknown'}`
      left.appendChild(title)
      left.appendChild(meta)

      const right = document.createElement('div')
      right.className = 'itemBtns'
      const blockBtn = document.createElement('button')
      blockBtn.className = 'btn danger'
      blockBtn.innerHTML = '<i class="fa-solid fa-ban"></i> Block'
      blockBtn.onclick = () => blockUser(user.ip)

      const unblockBtn = document.createElement('button')
      unblockBtn.className = 'btn'
      unblockBtn.innerHTML = '<i class="fa-solid fa-unlock"></i> Unblock'
      unblockBtn.onclick = () => unblockUser(user.ip)

      right.appendChild(blockBtn)
      right.appendChild(unblockBtn)

      top.appendChild(left)
      top.appendChild(right)
      li.appendChild(top)
      usersListEl.appendChild(li)
    })
  }

  socket.on('activeUsersUpdate', (data) => {
    renderUsers(data?.users || [])
  })

  function blockUser(ip) {
    fetch('/api/block-user', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip })
    })
      .then(r => r.json())
      .then(res => alert(res.status === 'success' ? `Blocked ${ip}` : `Failed: ${res.message || 'Unknown error'}`))
      .catch(() => alert('Failed to block user'))
  }

  function unblockUser(ip) {
    fetch('/api/unblock-user', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip })
    })
      .then(r => r.json())
      .then(res => alert(res.status === 'success' ? `Unblocked ${ip}` : `Failed: ${res.message || 'Unknown error'}`))
      .catch(() => alert('Failed to unblock user'))
  }

  logoutBtn.addEventListener('click', () => {
    fetch('/logout', { method: 'POST', credentials: 'include' })
      .then(() => {
        document.cookie = 'token=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/'
        window.location.href = '/auth'
      })
      .catch(() => {})
  })

  function colorForBlock(d) {
    const latency = parseInt(d.latency, 10)
    if ((d.status || '').toLowerCase() !== 'online') return '#ff4d4d'
    if (Number.isFinite(latency) && latency > 100) return '#ffcc00'
    return '#26d07c'
  }

  function createTimelineBlock(d) {
    const block = document.createElement('div')
    block.className = 'tblock'
    block.style.backgroundColor = colorForBlock(d)

    const tip = document.createElement('div')
    tip.className = 'tip'
    tip.textContent = `Time: ${d.timestamp}\nBot: ${d.botName}\nUptime: ${d.uptime}\nLatency: ${d.latency}\nMemory: ${d.memoryUsage}`
    block.appendChild(tip)
    return block
  }

  function renderTimeline() {
    timelineContainer.innerHTML = ''
    timelineData.forEach(d => timelineContainer.appendChild(createTimelineBlock(d)))
  }

  function saveTimelineData(entry) {
    fetch('/api/timeline', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(entry)
    }).catch(() => {})
  }

  fetch('/api/timeline')
    .then(r => r.json())
    .then(data => {
      timelineData = Array.isArray(data) ? data : []
      if (timelineData.length > MAX_MINUTES) timelineData = timelineData.slice(-MAX_MINUTES)
      renderTimeline()
    })
    .catch(() => {})

  function addTimelineBlock(data) {
    const now = Date.now()
    const blockData = { ...data, rawTimestamp: now, timestamp: new Date(now).toLocaleTimeString() }
    timelineData.push(blockData)
    if (timelineData.length > MAX_MINUTES) timelineData.shift()
    saveTimelineData(blockData)
    renderTimeline()
  }

  socket.on('botStatusUpdate', (data) => {
    addTimelineBlock(data || {})
  })

  function buildCurlUpload(host, apiKey) {
    return `curl -i -X POST "${host}/upload" -H "Authorization: Bearer ${apiKey}" -F "file=@C:\\path\\to\\image.png"`
  }

  function buildCurlFetch(host, apiKey) {
    return `curl -i -X POST "${host}/fetch" -H "Authorization: Bearer ${apiKey}" -H "Content-Type: application/x-www-form-urlencoded" --data "url=https://example.com/image.png"`
  }

  genBtn.addEventListener('click', async () => {
    try {
      setKeyStatus('Generating...')
      generatedKey.value = ''
      curlUpload.value = ''
      curlFetch.value = ''

      const name = (keyNameEl.value || '').trim() || 'user'
      const rate = parseInt(keyRateEl.value || '30', 10)
      const scopes = keyScopesEl.value || 'upload,fetch'
      const never = keyNeverEl.value === '1'

      const res = await fetch('/api/image-host/keys/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, rate_per_minute: rate, scopes, never_expires: never })
      })
      const data = await res.json()
      if (!res.ok) throw new Error(typeof data?.error === 'string' ? data.error : JSON.stringify(data?.error || data))

      const host = data.image_host
      generatedKey.value = data.api_key || ''
      curlUpload.value = buildCurlUpload(host, data.api_key)
      curlFetch.value = buildCurlFetch(host, data.api_key)

      setKeyStatus(`Created ${data.key_id}`)
    } catch (err) {
      setKeyStatus(`Failed: ${err?.message || String(err)}`)
    }
  })
})
