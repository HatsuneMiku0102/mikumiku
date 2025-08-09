document.addEventListener('DOMContentLoaded', function() {
  const token = document.cookie.split('; ').find(v => v.startsWith('token='))?.split('=')[1]
  if (!token) {
    window.location.href = '/auth'
    return
  }
  const socket = io({ query: { connectionType: 'admin' } })
  const chartEl = document.getElementById('locationChart')
  const usersCountEl = document.getElementById('active-users-count')
  const usersListEl = document.getElementById('active-ip-list')
  const logoutBtn = document.getElementById('logout')
  if (!chartEl || !usersCountEl || !usersListEl || !logoutBtn) return
  const ctx = chartEl.getContext('2d')
  const locationChart = new Chart(ctx, {
    type: 'bar',
    data: { labels: [], datasets: [{ label: 'Visitors by Country', data: [], backgroundColor: 'rgba(54, 162, 235, 0.6)', borderColor: 'rgba(54, 162, 235, 1)', borderWidth: 1 }] },
    options: { responsive: true, scales: { y: { beginAtZero: true } } }
  })
  function updateChart(countryData) {
    const countries = countryData.map(i => i._id || 'Unknown')
    const counts = countryData.map(i => i.count)
    locationChart.data.labels = countries
    locationChart.data.datasets[0].data = counts
    locationChart.update()
  }
  fetch('/api/geo-data').then(r => r.json()).then(updateChart).catch(() => {})
  socket.on('geoDataUpdate', updateChart)
  socket.on('activeUsersUpdate', data => {
    usersCountEl.innerText = `Currently Active Users: ${data.users.length}`
    usersListEl.innerHTML = ''
    data.users.forEach(user => {
      const li = document.createElement('li')
      li.classList.add('ip-item')
      const types = Array.isArray(user.connectionTypes) ? user.connectionTypes.join(', ') : String(user.connectionTypes || '')
      li.innerText = `IP: ${user.ip}, Connection Types: ${types}`
      const blockBtn = document.createElement('button')
      blockBtn.innerText = 'Block'
      blockBtn.onclick = () => blockUser(user.ip)
      const unblockBtn = document.createElement('button')
      unblockBtn.innerText = 'Unblock'
      unblockBtn.onclick = () => unblockUser(user.ip)
      li.appendChild(blockBtn)
      li.appendChild(unblockBtn)
      usersListEl.appendChild(li)
    })
  })
  function blockUser(ip) {
    fetch('/api/block-user', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip }) })
      .then(r => r.json())
      .then(res => { alert(res.status === 'success' ? `User with IP ${ip} has been blocked.` : `Failed to block user: ${res.message || 'Unknown error'}`) })
      .catch(() => { alert('Failed to block user') })
  }
  function unblockUser(ip) {
    fetch('/api/unblock-user', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip }) })
      .then(r => r.json())
      .then(res => { alert(res.status === 'success' ? `User with IP ${ip} has been unblocked.` : `Failed to unblock user: ${res.message || 'Unknown error'}`) })
      .catch(() => { alert('Failed to unblock user') })
  }
  logoutBtn.addEventListener('click', () => {
    fetch('/logout', { method: 'POST', credentials: 'include' })
      .then(() => { document.cookie = 'token=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/'; window.location.href = '/auth' })
      .catch(() => {})
  })
})
