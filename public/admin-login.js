document.addEventListener('DOMContentLoaded', function() {

    console.log('Admin dashboard script loaded.');

    // Initialize the socket.io connection
    const socket = io();

    // Socket connection events
    socket.on('connect', () => {
        console.log('Socket connected successfully:', socket.id);
    });

    socket.on('connect_error', (error) => {
        console.error('Error connecting to socket:', error);
    });

    // Listen for active users update from server
    socket.on('activeUsersUpdate', (data) => {
        console.log('Active users data received:', data); // Log the received data

        const activeUsersCountElement = document.getElementById('active-users-count');
        if (data && data.users && Array.isArray(data.users)) {
            const activeUsersCount = data.users.length;
            activeUsersCountElement.innerText = `Currently Active Users: ${activeUsersCount}`;

            const locationDiv = document.getElementById('location');
            locationDiv.innerHTML = ''; // Clear previous content

            // Create a set to keep track of unique IPs
            const uniqueIps = new Set();

            // Loop through the users array and display each user's location info
            data.users.forEach(user => {
                // Check if the IP is already in the set
                if (!uniqueIps.has(user.ip)) {
                    uniqueIps.add(user.ip);
                    const locationInfo = `IP: ${user.ip}, City: ${user.city}, Region: ${user.region}, Country: ${user.country}`;
                    const locationElement = document.createElement('p');
                    locationElement.innerText = locationInfo;
                    locationDiv.appendChild(locationElement);
                }
            });

            console.log('Location data updated successfully.');
        } else {
            console.warn('No valid active users data found.');
            activeUsersCountElement.innerText = 'No active users found.';
        }
    });

    // Fetch location data from the backend
    console.log('Fetching location data from server...');
    fetch('/api/location')
        .then(response => {
            if (response.ok) {
                return response.json();
            } else {
                console.error('Error fetching location data, status code:', response.status);
                throw new Error('Error fetching location data');
            }
        })
        .then(data => {
            console.log('Location data received:', data);
            const locationDiv = document.getElementById('location');
            locationDiv.innerHTML = ''; // Clear previous content

            if (data && Array.isArray(data)) {
                data.forEach(user => {
                    const locationInfo = `IP: ${user.ip}, City: ${user.city}, Region: ${user.region}, Country: ${user.country}`;
                    const locationElement = document.createElement('p');
                    locationElement.innerText = locationInfo;
                    locationDiv.appendChild(locationElement);
                });
                console.log('Location data rendered successfully.');
            } else {
                console.warn('No valid location data found.');
                document.getElementById('location').innerText = 'No valid location data found.';
            }
        })
        .catch(error => {
            console.error('Error loading location data:', error);
            document.getElementById('location').innerText = 'Error loading location data';
        });

    // Logout logic
    const logoutButton = document.getElementById('logout');
    if (logoutButton) {
        logoutButton.addEventListener('click', () => {
            console.log('Logout button clicked.');
            fetch('/logout', { method: 'POST' })
                .then(() => {
                    console.log('Logout request successful. Redirecting to login page...');
                    document.cookie = 'token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
                    window.location.href = '/admin-login.html';
                })
                .catch(error => {
                    console.error('Error during logout:', error);
                });
        });
    } else {
        console.warn('Logout button not found in the document.');
    }

    // Fetch YouTube API Status
    console.log('Checking YouTube API status...');
    fetch('/api/check-youtube')
        .then(response => {
            if (response.ok) {
                return response.json();
            } else if (response.status === 401) {
                return response.json().then(data => {
                    if (data.redirect) {
                        console.warn('Unauthorized access, redirecting to:', data.redirect);
                        window.location.href = data.redirect;
                    }
                });
            } else {
                console.error('Error checking YouTube API, status code:', response.status);
                throw new Error('Error checking YouTube API');
            }
        })
        .then(data => {
            if (data) {
                const youtubeStatus = document.getElementById('youtube-status');
                youtubeStatus.innerText = data.status;
                youtubeStatus.classList.add(data.available ? 'working' : 'unavailable');
                console.log('YouTube API status:', data.status);
            }
        })
        .catch(error => {
            console.error('Error checking YouTube API:', error);
        });

    // Fetch Bungie API Status
    console.log('Checking Bungie API status...');
    fetch('/api/check-bungie')
        .then(response => {
            if (response.ok) {
                return response.json();
            } else if (response.status === 401) {
                return response.json().then(data => {
                    if (data.redirect) {
                        console.warn('Unauthorized access, redirecting to:', data.redirect);
                        window.location.href = data.redirect;
                    }
                });
            } else {
                console.error('Error checking Bungie API, status code:', response.status);
                throw new Error('Error checking Bungie API');
            }
        })
        .then(data => {
            if (data) {
                const bungieStatus = document.getElementById('bungie-status');
                bungieStatus.innerText = data.status;
                bungieStatus.classList.add(data.available ? 'working' : 'unavailable');
                console.log('Bungie API status:', data.status);
            }
        })
        .catch(error => {
            console.error('Error checking Bungie API:', error);
        });
});
