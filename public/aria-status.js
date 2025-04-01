document.addEventListener('DOMContentLoaded', function() {
  const socket = io();
  let lastUpdateTime = Date.now();
  const OFFLINE_TIMEOUT = 90000;
  let timelineData = [];
  const MAX_MINUTES = 60;

  // Dynamically update the timeline summary based on entries within the last hour
  function updateTimelineSummary() {
    const oneHourAgo = Date.now() - 3600000;
    let offlineCount = 0;
    let highLatencyCount = 0;
    let normalOnlineCount = 0;

    timelineData.forEach(item => {
      if (item.rawTimestamp >= oneHourAgo) {
        if (item.status !== 'online') {
          offlineCount++;
        } else if (parseInt(item.latency) > 100) {
          highLatencyCount++;
        } else {
          normalOnlineCount++;
        }
      }
    });

    const summaryText = 
`Last hour:
Online (Normal)  : ${normalOnlineCount}
High Latency     : ${highLatencyCount}
Offline          : ${offlineCount}`;

    document.getElementById('timeline-summary').innerText = summaryText;
  }

  function renderTimeline() {
    const timelineContainer = document.getElementById('timeline-container');
    timelineContainer.innerHTML = '';

    timelineData.forEach(item => {
      const block = document.createElement('div');
      block.classList.add('timeline-block');

      // Color code the block
      if (item.status !== 'online') {
        block.style.backgroundColor = '#e74c3c'; // red
      } else if (parseInt(item.latency) > 100) {
        block.style.backgroundColor = '#f1c40f'; // yellow
      } else {
        block.style.backgroundColor = '#2ecc71'; // green
      }

      const tooltip = document.createElement('div');
      tooltip.classList.add('tooltip');
      tooltip.innerText = 
`Time   : ${item.timestamp}
Bot    : ${item.botName}
Uptime : ${item.uptime}
Latency: ${item.latency}
Memory : ${item.memoryUsage}`;
      block.appendChild(tooltip);
      timelineContainer.appendChild(block);
    });

    updateTimelineSummary();
  }

  function addTimelineBlock(data) {
    const now = Date.now();
    if (timelineData.length >= MAX_MINUTES) {
      timelineData.shift();
    }
    const blockData = {
      ...data,
      rawTimestamp: now,
      timestamp: new Date(now).toLocaleTimeString()
    };
    timelineData.push(blockData);
    saveTimelineData(blockData);
    renderTimeline();
  }

  function saveTimelineData(entry) {
    fetch('/api/timeline', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(entry)
    })
    .then(response => response.json())
    .catch(err => console.error('Error saving timeline entry:', err));
  }

  function markBotCompletelyOffline() {
    const statusText = document.getElementById('bot-status-text');
    statusText.textContent = 'Offline';
    statusText.classList.remove('status-online', 'status-high-latency');
    statusText.classList.add('status-offline');
    document.getElementById('bot-name').innerText = 'N/A';
    document.getElementById('bot-uptime').innerText = 'N/A';
    document.getElementById('bot-latency').innerText = 'N/A';
    document.getElementById('bot-memory').innerText = 'N/A';
  }

  function handleBotStatusUpdate(data) {
    lastUpdateTime = Date.now();
    const statusText = document.getElementById('bot-status-text');
    statusText.classList.remove('status-online','status-offline','status-high-latency');

    if (data.status === 'online') {
      if (parseInt(data.latency) > 100) {
        statusText.textContent = 'Online (High Latency)';
        statusText.classList.add('status-high-latency');
      } else {
        statusText.textContent = 'Online';
        statusText.classList.add('status-online');
      }
    } else {
      statusText.textContent = 'Offline';
      statusText.classList.add('status-offline');
    }

    document.getElementById('bot-name').innerText = data.botName || 'N/A';
    document.getElementById('bot-uptime').innerText = data.uptime || 'N/A';
    document.getElementById('bot-latency').innerText = data.latency || 'N/A';
    document.getElementById('bot-memory').innerText = data.memoryUsage || 'N/A';

    addTimelineBlock(data);
  }

  // Periodically update summary in case entries age out
  setInterval(updateTimelineSummary, 5000);

  setInterval(() => {
    if (Date.now() - lastUpdateTime > OFFLINE_TIMEOUT) {
      markBotCompletelyOffline();
    }
  }, 5000);

  socket.on('botStatusUpdate', handleBotStatusUpdate);

  fetch('/api/timeline')
    .then(response => response.json())
    .then(data => {
      timelineData = data || [];
      renderTimeline();
    })
    .catch(error => console.error('Error fetching timeline data:', error));
});
