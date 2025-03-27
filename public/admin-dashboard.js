document.addEventListener('DOMContentLoaded', function() {
    console.log('Admin dashboard script loaded.');
    const cookieString = document.cookie;
    console.log('Current cookies:', cookieString);
    const token = cookieString.split('; ').find(row => row.startsWith('token='))?.split('=')[1];
    if (!token) {
        console.warn('No valid token found, redirecting to login page.');
        window.location.href = '/auth';
    } else {
        console.log('Valid token detected:', token);
        const socket = io();
        const ctx = document.getElementById('locationChart').getContext('2d');
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
        });
        function updateChart(countryData) {
            const countries = countryData.map(item => item._id || 'Unknown');
            const visitCounts = countryData.map(item => item.count);
            locationChart.data.labels = countries;
            locationChart.data.datasets[0].data = visitCounts;
            locationChart.update();
        }
        fetch('/api/geo-data')
            .then(response => response.json())
            .then(data => {
                updateChart(data);
            })
            .catch(error => console.error('Error fetching initial geo data:', error));
        socket.on('geoDataUpdate', (data) => {
            console.log('Received geoDataUpdate:', data);
            updateChart(data);
        });
        socket.on('activeUsersUpdate', (data) => {
            console.log('Active users data received:', data);
            document.getElementById('active-users-count').innerText = `Currently Active Users: ${data.users.length}`;
            const activeIpListElement = document.getElementById('active-ip-list');
            activeIpListElement.innerHTML = '';
            data.users.forEach(user => {
                const ipItem = createIpItem(user);
                activeIpListElement.appendChild(ipItem);
            });
        });
        function createIpItem(user) {
            const ipItem = document.createElement('li');
            ipItem.classList.add('ip-item');
            const connectionTypes = Array.from(user.connectionTypes).join(', ');
            ipItem.innerText = `IP: ${user.ip}, Connection Types: ${connectionTypes}`;
            const blockButton = document.createElement('button');
            blockButton.innerText = 'Block';
            blockButton.onclick = () => blockUser(user.ip);
            const unblockButton = document.createElement('button');
            unblockButton.innerText = 'Unblock';
            unblockButton.onclick = () => unblockUser(user.ip);
            ipItem.appendChild(blockButton);
            ipItem.appendChild(unblockButton);
            return ipItem;
        }
        function blockUser(ip) {
            console.log(`Block button clicked for IP: ${ip}`);
            socket.emit('blockUser', { ip }, (response) => {
                console.log(`Response from blocking user:`, response);
                if (response.status === 'success') {
                    alert(`User with IP ${ip} has been blocked.`);
                } else {
                    alert(`Failed to block user: ${response.message}`);
                }
            });
        }
        function unblockUser(ip) {
            console.log(`Unblock button clicked for IP: ${ip}`);
            socket.emit('unblockUser', { ip }, (response) => {
                console.log(`Response from unblocking user:`, response);
                if (response.status === 'success') {
                    alert(`User with IP ${ip} has been unblocked.`);
                } else {
                    alert(`Failed to unblock user: ${response.message}`);
                }
            });
        }
        document.getElementById('logout').addEventListener('click', () => {
            console.log('Logout initiated.');
            fetch('/logout', { method: 'POST', credentials: 'include' })
                .then(() => {
                    console.log('Logout request successful, clearing token cookie.');
                    document.cookie = 'token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
                    window.location.href = '/auth';
                })
                .catch(error => {
                    console.error('Logout failed:', error);
                });
        });
        function updateBotStatus() {
            fetch('/status-proxy')
                .then(response => response.json())
                .then(data => {
                    const botStatusIndicator = document.getElementById('bot-status-indicator');
                    const botStatusText = document.getElementById('bot-status-text');
                    if (data.status === 'online') {
                        botStatusIndicator.querySelector('.status-indicator').classList.remove('status-offline');
                        botStatusIndicator.querySelector('.status-indicator').classList.add('status-online');
                        botStatusText.innerText = 'Online';
                    } else {
                        botStatusIndicator.querySelector('.status-indicator').classList.remove('status-online');
                        botStatusIndicator.querySelector('.status-indicator').classList.add('status-offline');
                        botStatusText.innerText = 'Offline';
                    }
                })
                .catch(error => {
                    const botStatusIndicator = document.getElementById('bot-status-indicator');
                    const botStatusText = document.getElementById('bot-status-text');
                    botStatusIndicator.querySelector('.status-indicator').classList.remove('status-online');
                    botStatusIndicator.querySelector('.status-indicator').classList.add('status-offline');
                    botStatusText.innerText = 'Offline';
                });
        }
        setInterval(updateBotStatus, 5000);
        updateBotStatus();
    }
});
