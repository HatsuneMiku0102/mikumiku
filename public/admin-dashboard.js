document.addEventListener('DOMContentLoaded', function() {
  const cookieString = document.cookie
  const token = cookieString.split('; ').find(row => row.startsWith('token='))?.split('=')[1]
  if (!token) {
    window.location.href = '/auth'
  } else {
    const socket = io()
    const ctx = document.getElementById('locationChart').getContext('2d')
    const locationChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: [],
        datasets: [{
          label: 'Visitors by Country',
          data: [],
          backgroundColor: 'rgba(54, 162, 235, 0.6)',
          borderColor: 'rgba(54, 162, 235, 1)',
          borderWidth: 1
        }]
      },
      options: {
        responsive: true,
        scales: {
          y: {
            beginAtZero: true
          }
        }
      }
    })
    function updateChart(countryData) {
      const countries = countryData.map(item => item._id || 'Unknown')
      const visitCounts = countryData.map(item => item.count)
      locationChart.data.labels = countries
      locationChart.data.datasets[0].data = visitCounts
      locationChart.update()
    }
    fetch('/api/geo-data')
      .then(response => response.json())
      .then(data => {
        updateChart(data)
      })
      .catch(error => console.error('Error fetching initial geo data:', error))
    socket.on('geoDataUpdate', (data) => {
      updateChart(data)
    })
    socket.on('activeUsersUpdate', (data) => {
      document.getElementById('active-users-count').innerText = `Currently Active Users: ${data.users.length}`
      const activeIpListElement = document.getElementById('active-ip-list')
      activeIpListElement.innerHTML = ''
      data.users.forEach(user => {
        const ipItem = createIpItem(user)
        activeIpListElement.appendChild(ipItem)
      })
    })
    function createIpItem(user) {
      const ipItem = document.createElement('li')
      ipItem.classList.add('ip-item')
      const connectionTypes = Array.from(user.connectionTypes).join(', ')
      ipItem.innerText = `IP: ${user.ip}, Connection Types: ${connectionTypes}`
      const blockButton = document.createElement('button')
      blockButton.innerText = 'Block'
      blockButton.onclick = () => blockUser(user.ip)
      const unblockButton = document.createElement('button')
      unblockButton.innerText = 'Unblock'
      unblockButton.onclick = () => unblockUser(user.ip)
      ipItem.appendChild(blockButton)
      ipItem.appendChild(unblockButton)
      return ipItem
    }
    function blockUser(ip) {
      socket.emit('blockUser', { ip }, (response) => {
        if (response.status === 'success') {
          alert(`User with IP ${ip} has been blocked.`)
        } else {
          alert(`Failed to block user: ${response.message}`)
        }
      })
    }
    function unblockUser(ip) {
      socket.emit('unblockUser', { ip }, (response) => {
        if (response.status === 'success') {
          alert(`User with IP ${ip} has been unblocked.`)
        } else {
          alert(`Failed to unblock user: ${response.message}`)
        }
      })
    }
    document.getElementById('logout').addEventListener('click', () => {
      fetch('/logout', { method: 'POST', credentials: 'include' })
        .then(() => {
          document.cookie = 'token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;'
          window.location.href = '/auth'
        })
        .catch(error => {
          console.error('Logout failed:', error)
        })
    })
    socket.on('toggleState', (data) => {
      document.getElementById('lfgToggle').checked = data.commands_enabled
    })
    socket.on('toggleUpdated', (data) => {
      document.getElementById('lfgToggle').checked = data.commands_enabled
    })
    document.getElementById('lfgToggle').addEventListener('change', function() {
      const newState = this.checked
      socket.emit('toggleCommands', { commands_enabled: newState })
    })
    socket.emit('getToggleState')
  }
})
