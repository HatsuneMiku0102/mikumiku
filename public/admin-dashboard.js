// admin-dashboard.js

document.addEventListener('DOMContentLoaded', function () {
    console.log('Admin dashboard script loaded.');

    // Establish Socket.IO connection
    const socket = io('https://your-server-domain.com'); // Replace with your server URL

    const activeUsersCountElement = document.getElementById('active-users-count');
    const userTableBody = document.getElementById('user-table-body');
    const selectedUserDetails = document.getElementById('selected-user-details');
    const logoutButton = document.getElementById('logout');

    // Handle Logout
    logoutButton.addEventListener('click', () => {
        console.log('Logout initiated.');
        fetch('/logout', { method: 'POST', credentials: 'include' })
            .then(() => {
                console.log('Logout successful. Redirecting to login page.');
                window.location.href = '/admin-login.html';
            })
            .catch(error => {
                console.error('Logout failed:', error);
            });
    });

    // Handle successful connection
    socket.on('connect', () => {
        console.log('Connected to Socket.IO server.');

        // Optionally, register as admin (if required by the server)
        socket.emit('register', { role: 'admin' });
    });

    // Handle connection errors
    socket.on('connect_error', (error) => {
        console.error('Connection error:', error);
    });

    // Listen for activeUsersUpdate event
    socket.on('activeUsersUpdate', (data) => {
        console.log('Active users data received:', data);
        if (data && data.users) {
            const users = data.users;
            activeUsersCountElement.innerText = `Currently Active Users: ${users.length}`;
            renderUserTable(users);
            updateCountryChart(users);
        } else {
            console.warn('Invalid activeUsersUpdate data received.');
            activeUsersCountElement.innerText = 'No active users found.';
            userTableBody.innerHTML = '<tr><td colspan="5">No active users found.</td></tr>';
        }
    });

    // Listen for presenceUpdate event (Optional: For real-time presence)
    socket.on('presenceUpdate', (data) => {
        console.log('Presence update received:', data);
        // Implement additional UI updates if needed
    });

    // Listen for updateVideoProgress event (Optional: For video tracking)
    socket.on('updateVideoProgress', (data) => {
        console.log('Video progress update received:', data);
        // Implement additional UI updates if needed
    });

    /**
     * Render the user table with active users data
     * @param {Array} users - Array of active user objects
     */
    function renderUserTable(users) {
        if (users.length === 0) {
            userTableBody.innerHTML = '<tr><td colspan="5">No active users found.</td></tr>';
            return;
        }

        userTableBody.innerHTML = ''; // Clear existing rows

        users.forEach(user => {
            const tr = document.createElement('tr');
            tr.dataset.socketId = user.socketId;

            const socketIdTd = document.createElement('td');
            socketIdTd.innerText = user.socketId;
            tr.appendChild(socketIdTd);

            const ipTd = document.createElement('td');
            ipTd.innerText = user.ip;
            tr.appendChild(ipTd);

            const locationTd = document.createElement('td');
            locationTd.innerText = `${user.city}, ${user.region}, ${user.country}`;
            tr.appendChild(locationTd);

            const userAgentTd = document.createElement('td');
            userAgentTd.innerText = user.userAgent;
            tr.appendChild(userAgentTd);

            const connectedAtTd = document.createElement('td');
            const connectedDate = new Date(user.connectedAt);
            connectedAtTd.innerText = connectedDate.toLocaleString();
            tr.appendChild(connectedAtTd);

            // Add click event to show user details
            tr.addEventListener('click', () => {
                displayUserDetails(user);
            });

            userTableBody.appendChild(tr);
        });
    }

    /**
     * Display detailed information about a selected user
     * @param {Object} user - User object containing detailed information
     */
    function displayUserDetails(user) {
        selectedUserDetails.innerHTML = `
            <p><strong>Socket ID:</strong> ${user.socketId}</p>
            <p><strong>IP Address:</strong> ${user.ip}</p>
            <p><strong>Location:</strong> ${user.city}, ${user.region}, ${user.country}</p>
            <p><strong>User Agent:</strong> ${user.userAgent}</p>
            <p><strong>Connected At:</strong> ${new Date(user.connectedAt).toLocaleString()}</p>
        `;
    }

    /**
     * Update the visitors by country chart
     * @param {Array} users - Array of active user objects
     */
    function updateCountryChart(users) {
        const countryCounts = {};
        users.forEach(user => {
            const country = user.country || 'Unknown';
            countryCounts[country] = (countryCounts[country] || 0) + 1;
        });

        const countries = Object.keys(countryCounts);
        const counts = Object.values(countryCounts);

        // Destroy existing chart if it exists
        if (window.locationChart) {
            window.locationChart.destroy();
        }

        const ctx = document.getElementById('locationChart').getContext('2d');
        window.locationChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: countries,
                datasets: [{
                    label: 'Visitors by Country',
                    data: counts,
                    backgroundColor: 'rgba(54, 162, 235, 0.6)',
                    borderColor: 'rgba(54, 162, 235, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                }
            }
        });
    }
});
