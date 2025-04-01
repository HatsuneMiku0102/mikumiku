document.addEventListener('DOMContentLoaded', function() {
  const socket = io()
  let lastUpdateTime = Date.now()
  const OFFLINE_TIMEOUT = 90000
  function markBotCompletelyOffline() {
    const statusText = document.getElementById('bot-status-text')
    statusText.textContent = 'Offline'
    statusText.classList.remove('status-online','status-high-latency')
    statusText.classList.add('status-offline')
    document.getElementById('bot-name').innerText = 'N/A'
    document.getElementById('bot-uptime').innerText = 'N/A'
    document.getElementById('bot-latency').innerText = 'N/A'
    document.getElementById('bot-memory').innerText = 'N/A'
  }
  setInterval(() => {
    if (Date.now() - lastUpdateTime > OFFLINE_TIMEOUT) {
      markBotCompletelyOffline()
    }
  }, 5000)
  socket.on('botStatusUpdate', (data) => {
    lastUpdateTime = Date.now()
    const statusText = document.getElementById('bot-status-text')
    statusText.classList.remove('status-online','status-offline','status-high-latency')
    if (data.status === 'online') {
      if (parseInt(data.latency) > 100) {
        statusText.textContent = 'Online (High Latency)'
        statusText.classList.add('status-high-latency')
      } else {
        statusText.textContent = 'Online'
        statusText.classList.add('status-online')
      }
    } else {
      statusText.textContent = 'Offline'
      statusText.classList.add('status-offline')
    }
    document.getElementById('bot-name').innerText = data.botName || 'N/A'
    document.getElementById('bot-uptime').innerText = data.uptime || 'N/A'
    document.getElementById('bot-latency').innerText = data.latency || 'N/A'
    document.getElementById('bot-memory').innerText = data.memoryUsage || 'N/A'
    addTimelineBlock(data)
  })
  let timelineData = []
  const MAX_MINUTES = 60
  function saveTimelineData(entry) {
    fetch('/api/timeline', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(entry)
    })
    .then(response => response.json())
    .then(data => {})
    .catch(err => {})
  }
  function renderTimeline() {
    const timelineContainer = document.getElementById('timeline-container')
    timelineContainer.innerHTML = ''
    timelineData.forEach(item => {
      const block = document.createElement('div')
      block.classList.add('timeline-block')
      if (item.status !== 'online') {
        block.style.backgroundColor = '#dc3545'
      } else if (parseInt(item.latency) > 100) {
        block.style.backgroundColor = '#ffc107'
      } else {
        block.style.backgroundColor = '#28a745'
      }
      const tooltip = document.createElement('div')
      tooltip.classList.add('tooltip')
      tooltip.innerText = `Time: ${item.timestamp}\nBot: ${item.botName}\nUptime: ${item.uptime}\nLatency: ${item.latency}\nMemory: ${item.memoryUsage}`
      block.appendChild(tooltip)
      timelineContainer.appendChild(block)
    })
  }
  function addTimelineBlock(data) {
    const now = Date.now()
    if (timelineData.length >= MAX_MINUTES) {
      timelineData.shift()
    }
    const blockData = {
      ...data,
      rawTimestamp: now,
      timestamp: new Date(now).toLocaleTimeString()
    }
    timelineData.push(blockData)
    saveTimelineData(blockData)
    renderTimeline()
  }
  fetch('/api/timeline')
    .then(response => response.json())
    .then(data => {
      timelineData = data || []
      renderTimeline()
    })
    .catch(error => {})
})
