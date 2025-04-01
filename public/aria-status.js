document.addEventListener('DOMContentLoaded', function() {
  console.log('Aria status script loaded.')
  const socket = io()
  let lastUpdateTime = Date.now()
  const OFFLINE_TIMEOUT = 90 * 1000
  function markBotCompletelyOffline() {
    document.getElementById('bot-status-text').textContent = 'Offline'
    document.getElementById('bot-status-text').classList.remove('status-online','status-high-latency')
    document.getElementById('bot-status-text').classList.add('status-offline')
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
    .then(data => console.log('Timeline entry saved:', data))
    .catch(err => console.error('Error saving timeline entry:', err))
  }
  function renderTimeline() {
    const timelineContainer = document.getElementById('timeline-container')
    timelineContainer.innerHTML = ''
    timelineData.forEach(data => {
      const block = createTimelineBlock(data)
      timelineContainer.appendChild(block)
    })
  }
  function createTimelineBlock(data) {
    const block = document.createElement('div')
    block.classList.add('timeline-block')
    if (data.status !== 'online') {
      block.style.backgroundColor = '#dc3545'
    } else if (parseInt(data.latency) > 100) {
      block.style.backgroundColor = '#ffc107'
    } else {
      block.style.backgroundColor = '#28a745'
    }
    const tooltip = document.createElement('div')
    tooltip.classList.add('tooltip')
    tooltip.innerText = `Time: ${data.timestamp}\nBot: ${data.botName}\nUptime: ${data.uptime}\nLatency: ${data.latency}\nMemory: ${data.memoryUsage}`
    block.appendChild(tooltip)
    return block
  }
  function addTimelineBlock(data) {
    const now = Date.now()
    if (timelineData.length >= MAX_MINUTES) {
      timelineData.shift()
    }
    const blockData = Object.assign({}, data, { rawTimestamp: now, timestamp: new Date(now).toLocaleTimeString() })
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
    .catch(error => console.error('Error fetching timeline data:', error))
})
